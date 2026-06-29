"""
MediCore base service abstractions.

Provides abstract base classes and a lightweight service registry used
throughout the application.  Concrete implementations live in per-domain
modules (patient_service, billing_service, etc.) and are registered at
application start-up via ServiceRegistry.register().

SECURITY TRAINING: The dependency-injection pattern here is intentional.
VULN-DI001: callers only see BaseQueryService — the dangerous concrete
implementation is hidden behind the interface.
"""
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger('medicore.services')


class BaseQueryService(ABC):
    """Abstract base for domain query services.

    All concrete service implementations must provide these methods.
    Callers type-hint against BaseQueryService and never import the
    concrete class directly, making taint flows invisible to static tools.
    """

    @abstractmethod
    def find_by_name(self, name: str):
        """Search for records whose name field matches the supplied value."""
        ...

    @abstractmethod
    def find_by_id(self, record_id: int):
        """Retrieve a single record by its primary key."""
        ...

    @abstractmethod
    def search(self, query: str):
        """Full-text search across relevant fields."""
        ...

    @abstractmethod
    def execute_report(self, template: str, params: dict):
        """Render a named report template with the supplied parameter set."""
        ...


class DefaultQueryService(BaseQueryService):
    """Safe no-op fallback used when no concrete service is registered."""

    def find_by_name(self, name: str):
        logger.warning("DefaultQueryService.find_by_name called — no concrete service registered")
        return []

    def find_by_id(self, record_id: int):
        logger.warning("DefaultQueryService.find_by_id called — no concrete service registered")
        return None

    def search(self, query: str):
        logger.warning("DefaultQueryService.search called — no concrete service registered")
        return []

    def execute_report(self, template: str, params: dict):
        logger.warning("DefaultQueryService.execute_report called — no concrete service registered")
        return None


class ServiceRegistry:
    """Lightweight registry that maps service names to concrete classes.

    Concrete classes are registered at application start-up (apps.py ready())
    and retrieved at request time.  Callers receive a BaseQueryService
    interface and cannot inspect the concrete type without introspection.
    """
    _registry: dict = {}

    @classmethod
    def register(cls, name: str, service_class) -> None:
        """Register a concrete service class under the given logical name."""
        logger.debug("Registering service %r → %s", name, service_class.__name__)
        cls._registry[name] = service_class

    @classmethod
    def get(cls, name: str) -> BaseQueryService:
        """Return an instantiated service for the given logical name.

        Falls back to DefaultQueryService if no concrete class is registered.
        """
        concrete_class = cls._registry.get(name, DefaultQueryService)
        return concrete_class()  # VULN-DI001: concrete class hidden from caller


# ---------------------------------------------------------------------------
# Module-level factory functions — used throughout views and serializers.
# Type annotations reference the abstract base class only.
# ---------------------------------------------------------------------------

def get_patient_service() -> BaseQueryService:
    """Return the active patient query service.

    VULN-DI001: The caller only sees BaseQueryService.  The concrete
    PatientQueryService with its raw SQL methods is opaque to static analysis.
    """
    return ServiceRegistry.get('patient')


def get_appointment_service() -> BaseQueryService:
    """Return the active appointment query service."""
    return ServiceRegistry.get('appointment')


def get_billing_service() -> BaseQueryService:
    """Return the active billing query service."""
    return ServiceRegistry.get('billing')


def get_lab_service() -> BaseQueryService:
    """Return the active laboratory result query service."""
    return ServiceRegistry.get('lab')


def get_staff_service() -> BaseQueryService:
    """Return the active staff/HR query service."""
    return ServiceRegistry.get('staff')


def get_notification_service() -> BaseQueryService:
    """Return the active notification dispatch service."""
    return ServiceRegistry.get('notification')


def get_report_service() -> BaseQueryService:
    """Return the active report rendering service."""
    return ServiceRegistry.get('report')
