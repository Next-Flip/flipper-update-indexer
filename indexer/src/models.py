import re
import os
import json
import hashlib
import logging
import pathlib
from pydantic import BaseModel
from github import Github, Repository
from typing import List, ClassVar

from .settings import settings


class VersionFile(BaseModel):
    url: str
    target: str
    type: str
    sha256: str


class Version(BaseModel):
    version: str
    changelog: str
    timestamp: int
    files: List[VersionFile] = []

    def add_file(self, file: VersionFile) -> None:
        self.files.append(file)


class Channel(BaseModel):
    id: str
    title: str
    description: str
    versions: List[Version] = []

    def add_version(self, version: Version) -> None:
        self.versions.append(version)


class Index(BaseModel):
    channels: List[Channel] = []

    def add_channel(self, channel: Channel) -> None:
        self.channels.append(channel)


class PackFile(BaseModel):
    url: str
    type: str
    sha256: str


class PackStats(BaseModel):
    packs: int = 0
    anims: int = 0
    icons: int = 0
    passport: List[str] = []
    fonts: List[str] = []


class Pack(BaseModel):
    id: str
    name: str
    author: str
    source_url: str
    description: str
    files: List[PackFile] = []
    preview_urls: List[str] = []
    stats: PackStats = PackStats()

    def add_file(self, file: PackFile) -> None:
        self.files.append(file)

    def add_preview_url(self, preview_url: str) -> None:
        self.preview_urls.append(preview_url)


class Catalog(BaseModel):
    packs: List[Pack] = []

    def add_pack(self, pack: Pack) -> None:
        self.packs.append(pack)


class IndexerGithub:
    __repo: Repository.Repository = None
    __tags: List = []
    __releases: List = []
    __branches: List = []

    def login(self, token: str, repo_name: str, org_name: str) -> None:
        try:
            git = Github(token)
            org = git.get_organization(org_name)
            self.__repo = org.get_repo(repo_name)
        except Exception as e:
            logging.exception(e)
            raise e

    def __get_tags(self) -> None:
        try:
            github_tags = self.__repo.get_tags()
            self.__tags = [x.name for x in github_tags]
        except Exception as e:
            logging.exception(e)
            raise e

    def __get_releases(self) -> None:
        try:
            github_releases = self.__repo.get_releases()
            self.__releases = [x.title for x in github_releases]
        except Exception as e:
            logging.exception(e)
            raise e

    def __get_branches(self) -> None:
        try:
            github_branches = self.__repo.get_branches()
            self.__branches = [x.name for x in github_branches]
        except Exception as e:
            logging.exception(e)
            raise e

    def sync_info(self):
        self.__get_tags()
        self.__get_releases()
        self.__get_branches()

    def get_unstable_branch_names(self) -> List[str]:
        return [
            branch
            for branch in self.__branches
            if branch
            not in (
                "dev",
                "release",
            )
        ]

    """
        We need all stuff above (except login) for the delete_unlinked_directories function in repository.py
    """

    def is_branch_exist(self, branch: str) -> bool:
        return branch in self.__branches

    def is_release_exist(self, release: str) -> bool:
        return release in self.__releases

    def is_tag_exist(self, tag: str) -> bool:
        return tag in self.__tags

    def get_dev_version(self, branch: str) -> Version:
        try:
            commits = self.__repo.get_commits(branch)
            if commits.totalCount == 0:
                exception_msg = f"No commits found in {branch} branch!"
                logging.exception(exception_msg)
                raise Exception(exception_msg)
            last_commit = commits[0]
            changelog = ""
            for commit in commits.get_page(0):
                msg = (
                    commit.commit.message.splitlines()[0]
                    .replace("`", "")
                    .replace("__", "")
                    .replace("**", "")
                )
                msg = msg[:50] + ("..." if len(msg) > 50 else "")
                changelog += f"[`{commit.sha[:8]}`]({commit.html_url}): {msg} - [__{commit.author.login}__](https://github.com/{commit.author.login})\n"
            return Version(
                version=last_commit.sha[:8],
                changelog=changelog,
                timestamp=int(last_commit.commit.author.date.timestamp()),
            )
        except Exception as e:
            logging.exception(e)
            raise e

    def get_release_version(self) -> Version:
        releases = self.__repo.get_releases()
        if releases.totalCount == 0:
            logging.warning(f"No releases found for {self.__repo.full_name}!")
            return None
        try:
            last_release = next(filter(lambda c: not c.prerelease, releases))
            return Version(
                version=last_release.title,
                changelog=last_release.body.split("## 🚀 Changelog", 1)[-1].strip(),
                timestamp=int(last_release.created_at.timestamp()),
            )
        except StopIteration:
            return None


class FileParser(BaseModel):
    target: str = ""
    type: str = ""
    regex: ClassVar[re.Pattern] = re.compile(
        r"^flipper-z-(\w+)-(\w+)-mntm-([A-Za-z0-9_.-]+)\.(\w+)$"
    )

    def getSHA256(self, filepath: str) -> str:
        with open(filepath, "rb") as file:
            file_bytes = file.read()
            sha256 = hashlib.sha256(file_bytes).hexdigest()
        return sha256

    def parse(self, filename: str) -> None:
        match = self.regex.match(filename)
        if not match:
            exception_msg = f"Unknown file {filename}"
            logging.exception(exception_msg)
            raise Exception(exception_msg)
        self.target = match.group(1)
        self.type = match.group(2) + "_" + match.group(4)


class PackParser(BaseModel):
    anim_regex: ClassVar[re.Pattern] = re.compile(rb"^Name: ", re.MULTILINE)

    def getSHA256(self, filepath: str) -> str:
        with open(filepath, "rb") as file:
            file_bytes = file.read()
            sha256 = hashlib.sha256(file_bytes).hexdigest()
        return sha256

    def parse(self, packpath: str) -> Pack:
        pack_set = pathlib.Path(packpath)

        with open(pack_set / "meta.json", "r") as f:
            meta: dict = json.load(f)

        pack = Pack(
            id=pack_set.name,
            name=meta.get("name", pack_set.name.title()),
            author=meta.get("author", "N/A"),
            source_url=meta.get("source_url", ""),
            description=meta.get("description", ""),
        )

        for pack_entry in (pack_set / "source").iterdir():
            if not pack_entry.is_dir():
                continue
            anims = 0
            icons = 0
            passport = set()
            fonts = set()
            if (pack_entry / "Anims/manifest.txt").is_file():
                manifest = (pack_entry / "Anims/manifest.txt").read_bytes()
                anims = sum(1 for _ in self.anim_regex.finditer(manifest))
            if (pack_entry / "Icons").is_dir():
                for icon_set in (pack_entry / "Icons").iterdir():
                    if icon_set.name.startswith(".") or not icon_set.is_dir():
                        continue
                    for icon in icon_set.iterdir():
                        if icon.name.startswith("."):
                            continue
                        if icon.is_dir() and (
                            (icon / "frame_rate").is_file() or (icon / "meta").is_file()
                        ):
                            icons += 1
                        elif icon.is_file() and icon.suffix in (".png", ".bmx"):
                            if icon_set.name == "Passport":
                                parts = icon.name.split("_")
                                if len(parts) < 3:  # passport_128x64
                                    passport.add("Background")
                                else:
                                    passport.add(parts[1].title())
                            else:
                                icons += 1
            if (pack_entry / "Fonts").is_dir():
                for font in (pack_entry / "Fonts").iterdir():
                    if font.name.startswith(".") or not font.is_file():
                        continue
                    if font.suffix in (".c", ".u8f"):
                        fonts.add(font.stem)
            if anims or icons or passport or fonts:
                pack.stats.packs += 1
                pack.stats.anims += anims
                pack.stats.icons += icons
                pack.stats.passport = sorted(passport.union(pack.stats.passport))
                pack.stats.fonts = sorted(fonts.union(pack.stats.fonts))
            else:
                logging.warn(
                    f"Pack {pack_entry.name!r} in set {pack_set.name!r} is empty"
                )

        for file in (pack_set / "download").iterdir():
            if file.name.startswith(".") or not file.is_file():
                continue
            if file.name.endswith((".zip", ".tar.gz")):
                pack.add_file(
                    PackFile(
                        url=os.path.join(
                            settings.base_url, file.relative_to(settings.files_dir)
                        ),
                        type="pack_"
                        + file.suffix.removeprefix(".").replace("gz", "targz"),
                        sha256=self.getSHA256(file),
                    )
                )
        if len(pack.files) != 2:
            logging.warn(
                f"Pack {pack_set.name!r} has {len(pack.files)} file{'' if len(pack.files) == 1 else 's'}, "
                "should be 2 files (.zip and .tar.gz)"
            )

        for preview in sorted((pack_set / "preview").iterdir()):
            if preview.name.startswith(".") or not preview.is_file():
                continue
            if preview.suffix in (".png", ".jpg", ".gif"):
                pack.add_preview_url(
                    os.path.join(
                        settings.base_url, preview.relative_to(settings.files_dir)
                    )
                )
        if len(pack.preview_urls) not in range(1, 8):
            logging.warn(
                f"Pack {pack_set.name!r} has {len(pack.preview_urls)} previews, "
                "should be between 1 and 8"
            )

        return pack
