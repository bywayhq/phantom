"""HTTP requests with explicit browser profiles and protocols."""

from . import _native as _native
from . import _upload as _upload
from ._bodies import MultipartPart as MultipartPart
from ._bodies import PreparedBody as PreparedBody
from ._bodies import StreamingMultipartBody as StreamingMultipartBody
from ._certificates import ClientCertificate as ClientCertificate
from ._client import AsyncClient as AsyncClient
from ._configuration import INHERIT as INHERIT
from ._configuration import ConnectionRetry as ConnectionRetry
from ._configuration import ContentDecoding as ContentDecoding
from ._configuration import Header as Header
from ._configuration import Proxy as Proxy
from ._configuration import RedirectPolicy as RedirectPolicy
from ._configuration import RetryPolicy as RetryPolicy
from ._configuration import SessionSharing as SessionSharing
from ._configuration import StatusRetry as StatusRetry
from ._configuration import TimeoutOverrides as TimeoutOverrides
from ._configuration import Timeouts as Timeouts
from ._configuration import Trust as Trust
from ._diagnostics import RequestConnection as RequestConnection
from ._diagnostics import RequestDiagnostics as RequestDiagnostics
from ._diagnostics import RequestTimeline as RequestTimeline
from ._diagnostics import RequestTiming as RequestTiming
from ._diagnostics import TlsConnectionInfo as TlsConnectionInfo
from ._diagnostics import TlsConnectionState as TlsConnectionState
from ._errors import AttemptBudgetExhausted as AttemptBudgetExhausted
from ._errors import BodyLimitExceeded as BodyLimitExceeded
from ._errors import ClientClosed as ClientClosed
from ._errors import DecodeError as DecodeError
from ._errors import Error as Error
from ._errors import PreparedBodyError as PreparedBodyError
from ._errors import ProfileError as ProfileError
from ._errors import SessionSnapshotError as SessionSnapshotError
from ._errors import TimeoutError as TimeoutError
from ._errors import UploadError as UploadError
from ._errors import _call as _call
from ._errors import _error as _error
from ._errors import _primary_error as _primary_error
from ._errors import _upload_error as _upload_error
from ._network import HostOverride as HostOverride
from ._network import NetworkOptions as NetworkOptions
from ._pool import PoolOptions as PoolOptions
from ._profile import ImportedProfile as ImportedProfile
from ._profile import Profile as Profile
from ._request import _request_fields as _request_fields
from ._response import AsyncResponse as AsyncResponse
from ._response import RedirectHistory as RedirectHistory
from ._response import RedirectHop as RedirectHop
from ._response import ResponseHeader as ResponseHeader
from ._response import ResponseTrailers as ResponseTrailers
from ._session import AttemptBudget as AttemptBudget
from ._session import Cookies as Cookies
from ._sync import Client as Client
from ._sync import HTTPStatusError as HTTPStatusError
from ._sync import Response as Response
from ._transfer import TransferControl as TransferControl
from ._transfer import TransferLimits as TransferLimits
from ._transfer import TransferSnapshot as TransferSnapshot

# Preserve the public class path for introspection and serialization.
for _public_type in (
    Error,
    TimeoutError,
    AttemptBudgetExhausted,
    ClientClosed,
    BodyLimitExceeded,
    PreparedBodyError,
    UploadError,
    ProfileError,
    SessionSnapshotError,
    DecodeError,
    HTTPStatusError,
    MultipartPart,
    StreamingMultipartBody,
    PreparedBody,
    ClientCertificate,
    Profile,
    ImportedProfile,
    AttemptBudget,
    Cookies,
    RedirectHop,
    RedirectHistory,
    ResponseHeader,
    ResponseTrailers,
    AsyncResponse,
    Response,
    AsyncClient,
    Client,
):
    _public_type.__module__ = __name__
del _public_type
