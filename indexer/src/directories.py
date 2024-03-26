import logging
import asyncio
from fastapi import APIRouter
from fastapi.responses import JSONResponse, RedirectResponse, FileResponse

from .repository import indexes, RepositoryIndex, PacksCatalog


router = APIRouter()
lock = asyncio.Lock()


@router.get("/{directory}/directory.json")
async def directory_request(directory):
    """
    Method for obtaining indices
    Args:
        directory: Repository name

    Returns:
        Indices in json
    """
    if directory not in indexes:
        return JSONResponse(f"{directory} not found!", status_code=404)
    return indexes.get(directory).index


@router.get(
    "/{directory}/{channel}/{target}/{file_type}",
    response_class=RedirectResponse,
    status_code=302,
)
async def repository_latest_request(directory, channel, target, file_type):
    """
    A method for retrieving a file from the repository
    of a specific version
    Args:
        directory: Repository name
        channel: Channel type (release, dev)
        target: Operating System (linux, mac, win)
        file_type: File Type

    Returns:
        Artifact file
    """
    if directory not in indexes:
        return JSONResponse(f"{directory} not found!", status_code=404)
    index = indexes.get(directory)
    if not isinstance(index, RepositoryIndex):
        return JSONResponse("Path not found!", status_code=404)
    if len(index.index["channels"]) == 0:
        return JSONResponse("No channels found!", status_code=404)
    try:
        return index.get_file_from_latest_version(channel, target, file_type)
    except Exception as e:
        return JSONResponse(str(e), status_code=404)


@router.get("/{directory}/{channel}/{file_name}")
async def repository_file_request(directory, channel, file_name):
    """
    A method for retrieving a file from a specific version
    Args:
        directory: Repository name
        channel: Channel type (release, dev)
        file_name: File Name

    Returns:
        Artifact file
    """
    if directory not in indexes:
        return JSONResponse(f"{directory} not found!", status_code=404)
    index = indexes.get(directory)
    if not isinstance(index, RepositoryIndex):
        return JSONResponse("Path not found!", status_code=404)
    if len(index.index["channels"]) == 0:
        return JSONResponse("No channels found!", status_code=404)
    try:
        return FileResponse(
            index.get_file_path(channel, file_name),
            media_type="application/octet-stream",
            status_code=200,
        )
    except Exception as e:
        return JSONResponse(str(e), status_code=404)


@router.get("/{directory}/reindex")
async def reindex_request(directory):
    """
    Method for starting reindexing
    Args:
        directory: Repository name

    Returns:
        Reindex status
    """
    if directory not in indexes:
        return JSONResponse(f"{directory} not found!", status_code=404)
    async with lock:
        try:
            indexes.get(directory).reindex()
            return JSONResponse("Reindexing is done!")
        except Exception as e:
            logging.exception(e)
            return JSONResponse("Reindexing is failed!", status_code=500)
