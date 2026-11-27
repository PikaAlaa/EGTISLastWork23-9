"""Read-only recommended-action catalogue for the console (design core-v2 §2.4, §2.5).

GET only. No endpoint here, or anywhere else, performs an action: the texts are for a
person to read. Draft texts are left out unless ETIS_SHOW_DRAFT_ACTIONS is set.
"""
import logging

from fastapi import APIRouter, Depends

from app.core.security import verify_api_key
from app.routers.soc_common import error
from app.services.recommended_actions import CatalogueError, displayable_catalogue

router = APIRouter(tags=['recommended-actions'], dependencies=[Depends(verify_api_key)])
logger = logging.getLogger(__name__)


@router.get('/recommended-actions')
def get_recommended_actions():
    try:
        return displayable_catalogue()
    except CatalogueError as exc:
        logger.error('recommended_actions_catalogue_invalid', extra={'reason': str(exc)})
        return error(503, 'recommended_actions_unavailable')
