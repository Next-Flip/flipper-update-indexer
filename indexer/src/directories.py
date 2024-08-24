import logging
import asyncio
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse

from .repository import indexes, RepositoryIndex, PacksCatalog


router = APIRouter()
lock = asyncio.Lock()


@router.get("/")
async def root_request():
    """
    API root, redirect to firmware index
    """
    return RedirectResponse("/firmware", status_code=303)


def setup_routes(prefix: str, index):
    @router.get(prefix + "/directory.json")
    @router.get(prefix)
    async def directory_request():
        """
        Method for obtaining indices
        Args:
            Nothing

        Returns:
            Indices in json
        """
        return index.index

    if isinstance(index, RepositoryIndex):

        @router.get(
            prefix + "/{channel}/{target}/{file_type}",
            response_class=RedirectResponse,
            status_code=302,
        )
        async def repository_latest_request(channel, target, file_type):
            """
            A method for retrieving a file from the repository
            of a specific version
            Args:
                channel: Channel type (release, dev)
                target: Operating System (linux, mac, win)
                file_type: File Type

            Returns:
                Artifact file
            """
            if len(index.index["channels"]) == 0:
                return JSONResponse("No channels found!", status_code=404)
            try:
                return index.get_file_from_latest_version(channel, target, file_type)
            except Exception as e:
                return JSONResponse(str(e), status_code=404)

        @router.get(prefix + "/{channel}/{file_name}")
        async def repository_file_request(channel, file_name):
            """
            A method for retrieving a file from a specific version
            Args:
                channel: Channel type (release, dev)
                file_name: File Name

            Returns:
                Artifact file
            """
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

    elif isinstance(index, PacksCatalog):

        @router.get(prefix + "/{pack}/{file_type}/{file_name}")
        async def pack_file_request(pack, file_type, file_name):
            """
            A method for retrieving a file from a specific pack
            Args:
                pack: Pack id
                file_type: File Type (download, preview)
                file_name: File Name

            Returns:
                Artifact file
            """
            if len(index.index["packs"]) == 0:
                return JSONResponse("No packs found!", status_code=404)
            try:
                return FileResponse(
                    index.get_file_path(pack, file_type, file_name),
                    media_type="application/octet-stream",
                    status_code=200,
                )
            except Exception as e:
                return JSONResponse(str(e), status_code=404)

    @router.get(prefix + "/reindex")
    async def reindex_request():
        """
        Method for starting reindexing
        Args:
            Nothing

        Returns:
            Reindex status
        """
        async with lock:
            try:
                index.reindex()
                return JSONResponse("Reindexing is done!")
            except Exception as e:
                logging.exception(e)
                return JSONResponse("Reindexing is failed!", status_code=500)

    if isinstance(index, RepositoryIndex):

        @router.get(prefix + "/{branch}")
        async def repository_branch_request(branch):
            """
            A method for retrieving the list of files from a specific branch
            Made for support of `ufbt update --index-url {base_url}/firmware --branch {branch}`
            Args:
                branch: Branch name

            Returns:
                HTML links in format that ufbt understands
            """
            if len(index.index["channels"]) == 0:
                return JSONResponse("No channels found!", status_code=404)
            try:
                branch_files = index.get_branch_file_names(branch)
                response = "\n".join(f'<a href="{file}"></a>' for file in branch_files)
                return HTMLResponse(
                    response,
                    status_code=200,
                )
            except Exception as e:
                return JSONResponse(str(e), status_code=404)


for directory, index in indexes.items():
    setup_routes(f"/{directory}", index)
