"""Análisis en segundo plano con progreso consultable y cancelación.

La interfaz crea un trabajo, consulta su estado periódicamente y puede
cancelarlo; al cancelar, se devuelven los resultados obtenidos hasta entonces.
"""

from threading import Event, Lock, Thread
from time import monotonic
from uuid import uuid4

import requests

from app import history
from app.scanner import scan_website


MAX_STORED_JOBS = 20  # Se olvidan los trabajos terminados más antiguos


class ScanJob:
    def __init__(self, target: str, crawl: bool):
        self.id = uuid4().hex
        self.target = target
        self.crawl = crawl
        self.state = "running"  # running | done | cancelled | error
        self.progress: dict = {}
        self.result: dict | None = None
        self.history_entry: dict | None = None  # Resumen guardado en el historial
        self.error: str | None = None
        self.started_at = monotonic()
        self.finished_at: float | None = None
        self._cancel = Event()
        self._lock = Lock()

    def run(self) -> None:
        try:
            result = scan_website(
                self.target,
                crawl=self.crawl,
                on_progress=self._set_progress,
                should_cancel=self._cancel.is_set,
            )
            state = "cancelled" if self._cancel.is_set() else "done"
            try:
                saved = history.save(self.target, self.crawl, state, result)
            except OSError:
                saved = None  # Sin historial el análisis sigue siendo válido
            with self._lock:
                self.result = result
                self.history_entry = saved
                self.state = state
        except ValueError as exc:
            self._fail(str(exc))
        except requests.RequestException:
            self._fail("No se pudo conectar con el sitio web.")
        except Exception:  # Un fallo inesperado no debe dejar el trabajo colgado
            self._fail("Error inesperado durante el análisis.")
        finally:
            self.finished_at = monotonic()

    def cancel(self) -> None:
        self._cancel.set()

    def _set_progress(self, progress: dict) -> None:
        with self._lock:
            self.progress = progress

    def _fail(self, message: str) -> None:
        with self._lock:
            self.error = message
            self.state = "error"

    def snapshot(self) -> dict:
        with self._lock:
            end = self.finished_at or monotonic()
            return {
                "id": self.id,
                "state": self.state,
                "cancel_requested": self._cancel.is_set(),
                "elapsed_seconds": round(end - self.started_at, 1),
                "progress": dict(self.progress),
                "result": self.result,
                "history_entry": self.history_entry,
                "error": self.error,
            }


_jobs: dict[str, ScanJob] = {}
_jobs_lock = Lock()


def start_job(target: str, crawl: bool) -> ScanJob:
    job = ScanJob(target, crawl)
    with _jobs_lock:
        _forget_old_jobs()
        _jobs[job.id] = job
    Thread(target=job.run, daemon=True).start()
    return job


def get_job(job_id: str) -> ScanJob | None:
    with _jobs_lock:
        return _jobs.get(job_id)


def _forget_old_jobs() -> None:
    finished = [job for job in _jobs.values() if job.finished_at is not None]
    finished.sort(key=lambda job: job.finished_at)
    for job in finished[: max(0, len(_jobs) - MAX_STORED_JOBS + 1)]:
        del _jobs[job.id]
