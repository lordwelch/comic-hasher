from __future__ import annotations

import argparse
import itertools
import json
import logging
import pathlib
from datetime import datetime
from enum import auto
from io import BytesIO
from typing import Any
from typing import cast
from typing import TypedDict
from urllib.parse import urljoin

import appdirs
import comictaggerlib.cli
import imagehash
import requests
import settngs
from comicapi import comicarchive
from comicapi import merge
from comicapi import utils
from comicapi.genericmetadata import GenericMetadata
from comicapi.issuestring import IssueString
from comictalker.comiccacher import ComicCacher
from comictalker.comiccacher import Issue
from comictalker.comiccacher import Series
from comictalker.comictalker import ComicSeries
from comictalker.talker_utils import cleanup_html
from comictalker.talkers.comicvine import ComicVineTalker
from comictalker.talkers.comicvine import CVIssue
from comictalker.talkers.comicvine import CVResult
from comictalker.talkers.comicvine import CVSeries
from PIL import Image

logger = logging.getLogger('quick_tag')

__version__ = '0.1'


class CV(ComicVineTalker):
    def fetch_comics(self, *, issue_ids: list[str]) -> list[GenericMetadata]:
        # before we search online, look in our cache, since we might already have this info
        cvc = ComicCacher(self.cache_folder, self.version)
        cached_results: list[GenericMetadata] = []
        needed_issues: list[int] = []
        for issue_id in issue_ids:
            cached_issue = cvc.get_issue_info(issue_id, self.id)

            if cached_issue and cached_issue[1]:
                cached_results.append(
                    self._map_comic_issue_to_metadata(
                        json.loads(cached_issue[0].data), self._fetch_series([int(cached_issue[0].series_id)])[0][0],
                    ),
                )
            else:
                needed_issues.append(int(issue_id))  # CV uses integers for it's IDs

        if not needed_issues:
            return cached_results
        issue_filter = ""
        for iid in needed_issues:
            issue_filter += str(iid) + "|"
        flt = "id:" + issue_filter.rstrip('|')

        issue_url = urljoin(self.api_url, "issues/")
        params: dict[str, Any] = {
            "api_key": self.api_key,
            "format": "json",
            "filter": flt,
        }
        cv_response: CVResult[list[CVIssue]] = self._get_cv_content(issue_url, params)

        issue_results = cv_response["results"]
        page = 1
        offset = 0
        current_result_count = cv_response["number_of_page_results"]
        total_result_count = cv_response["number_of_total_results"]

        # see if we need to keep asking for more pages...
        while current_result_count < total_result_count:
            page += 1
            offset += cv_response["number_of_page_results"]

            params["offset"] = offset
            cv_response = self._get_cv_content(issue_url, params)

            issue_results.extend(cv_response["results"])
            current_result_count += cv_response["number_of_page_results"]

        series_info = {s[0].id: s[0] for s in self._fetch_series([int(i["volume"]["id"]) for i in issue_results])}

        for issue in issue_results:
            cvc.add_issues_info(
                self.id,
                [
                    Issue(
                        id=str(issue["id"]),
                        series_id=str(issue["volume"]["id"]),
                        data=json.dumps(issue).encode("utf-8"),
                    ),
                ],
                True,
            )
            cached_results.append(
                self._map_comic_issue_to_metadata(issue, series_info[str(issue["volume"]["id"])]),
            )

        return cached_results

    def _fetch_series(self, series_ids: list[int]) -> list[tuple[ComicSeries, bool]]:
        # before we search online, look in our cache, since we might already have this info
        cvc = ComicCacher(self.cache_folder, self.version)
        cached_results: list[tuple[ComicSeries, bool]] = []
        needed_series: list[int] = []
        for series_id in series_ids:
            cached_series = cvc.get_series_info(str(series_id), self.id)
            if cached_series is not None:
                cached_results.append((self._format_series(json.loads(cached_series[0].data)), cached_series[1]))
            else:
                needed_series.append(series_id)

        if needed_series == []:
            return cached_results

        series_filter = ""
        for vid in needed_series:
            series_filter += str(vid) + "|"
        flt = "id:" + series_filter.rstrip('|')  # CV uses volume to mean series

        series_url = urljoin(self.api_url, "volumes/")  # CV uses volume to mean series
        params: dict[str, Any] = {
            "api_key": self.api_key,
            "format": "json",
            "filter": flt,
        }
        cv_response: CVResult[list[CVSeries]] = self._get_cv_content(series_url, params)

        series_results = cv_response["results"]
        page = 1
        offset = 0
        current_result_count = cv_response["number_of_page_results"]
        total_result_count = cv_response["number_of_total_results"]

        # see if we need to keep asking for more pages...
        while current_result_count < total_result_count:
            page += 1
            offset += cv_response["number_of_page_results"]

            params["offset"] = offset
            cv_response = self._get_cv_content(series_url, params)

            series_results.extend(cv_response["results"])
            current_result_count += cv_response["number_of_page_results"]

        if series_results:
            for series in series_results:
                cvc.add_series_info(
                    self.id, Series(id=str(series["id"]), data=json.dumps(series).encode("utf-8")), True,
                )
                cached_results.append((self._format_series(series), True))

        return cached_results


class HashType(utils.StrEnum):
    AHASH = auto()
    DHASH = auto()
    PHASH = auto()


class SimpleResult(TypedDict):
    Distance: int
    # Mapping of domains (eg comicvine.gamespot.com) to IDs
    IDList: dict[str, list[str]]


class Hash(TypedDict):
    Hash: int
    Kind: str


class Result(TypedDict):
    # Mapping of domains (eg comicvine.gamespot.com) to IDs
    IDList: dict[str, list[str]]
    Distance: int
    Hash: Hash


def ihash(types: str) -> list[str]:
    result = []
    types = types.casefold()
    choices = ", ".join(HashType)
    for typ in utils.split(types, ","):
        if typ not in list(HashType):
            raise argparse.ArgumentTypeError(f"invalid choice: {typ} (choose from {choices.upper()})")
        result.append(HashType[typ.upper()])

    if not result:
        raise argparse.ArgumentTypeError(f"invalid choice: {types} (choose from {choices.upper()})")
    return result


def settings(manager: settngs.Manager):
    manager.add_setting(
        '--url', '-u', default='https://comic-hasher.narnian.us',
        type=utils.parse_url, help='Website to use for searching cover hashes',
    )
    manager.add_setting(
        '--max', '-m', default=8, type=int,
        help='Maximum score to allow. Lower score means more accurate',
    )
    manager.add_setting(
        '--simple', '-s', default=False, action=argparse.BooleanOptionalAction,
        help='Whether to retrieve simple results or full results',
    )
    manager.add_setting(
        '--force-interactive', '-f', default=True, action=argparse.BooleanOptionalAction,
        help='When not set will automatically tag comics that have a single match with a score of 4 or lower',
    )
    manager.add_setting(
        '--aggressive-filtering', '-a', default=False, action=argparse.BooleanOptionalAction,
        help='Will filter out worse matches if better matches are found',
    )
    manager.add_setting(
        '--hash', default=['ahash', 'dhash', 'phash'], type=ihash,
        help='Pick what hashes you want to use to search',
    )
    manager.add_setting(
        '--skip-non-exact', default=True, action=argparse.BooleanOptionalAction,
        help='Skip non-exact matches if we have exact matches',
    )
    manager.add_setting('--cv-api-key', '-c')
    manager.add_setting('comic_archive', type=pathlib.Path)


def SearchHashes(url: str, simple: bool, max: int, ahash: str, dhash: str, phash: str, skip_non_exact: bool) -> list[SimpleResult] | list[Result]:
    resp = requests.get(
        urljoin(url, '/match_cover_hash'),
        {
            'simple': simple,
            'max': max,
            'ahash': ahash,
            'dhash': dhash,
            'phash': phash,
            'skipNonExact': skip_non_exact,
        },
    )
    if resp.status_code != 200:
        try:
            text = resp.json()['msg']
        except Exception:
            text = resp.text
        logger.error('message from server: %s', text)
        raise SystemExit(3)
    return resp.json()['results']


def get_simple_results(results: list[SimpleResult], cv_api_key: str | None = None) -> list[tuple[int, GenericMetadata]]:
    cache_dir = pathlib.Path(appdirs.user_cache_dir('quick_tag'))
    cache_dir.mkdir(parents=True, exist_ok=True)
    cv = CV(f"quick_tag/{__version__}", cache_dir)
    cv.parse_settings({
        'comicvine_key': cv_api_key,
        'cv_use_series_start_as_volume': True,
    })
    md_results: list[tuple[int, GenericMetadata]] = []
    results.sort(key=lambda r: r['Distance'])
    all_cv_ids = set()
    for res in results:
        all_cv_ids.update(res['IDList']['comicvine.gamespot.com'])
    # Do a bulk feth of basic issue data
    mds = cv.fetch_comics(issue_ids=list(all_cv_ids))

    # Re-associate the md to the distance
    for res in results:
        for md in mds:
            if md.issue_id in res['IDList']['comicvine.gamespot.com']:
                md_results.append((res['Distance'], md))
    return md_results


def get_results(results: list[Result], cv_api_key: str | None = None) -> list[tuple[int, Hash, GenericMetadata]]:
    cache_dir = pathlib.Path(appdirs.user_cache_dir('quick_tag'))
    cache_dir.mkdir(parents=True, exist_ok=True)
    cv = CV(f"quick_tag/{__version__}", cache_dir)
    cv.parse_settings({
        'comicvine_key': cv_api_key,
        'cv_use_series_start_as_volume': True,
    })
    md_results: list[tuple[int, Hash, GenericMetadata]] = []
    results.sort(key=lambda r: r['Distance'])
    all_cv_ids = set()
    for res in results:
        all_cv_ids.update(res['IDList']['comicvine.gamespot.com'])
    # Do a bulk feth of basic issue data
    mds = cv.fetch_comics(issue_ids=list(all_cv_ids))

    # Re-associate the md to the distance
    for res in results:
        for md in mds:
            if md.issue_id in res['IDList']['comicvine.gamespot.com']:
                md_results.append((res['Distance'], res['Hash'], md))
    return md_results


def filter_simple_results(results: list[SimpleResult], force_interactive=True, aggressive_filtering=False) -> list[SimpleResult]:
    if not force_interactive:
        # If there is a single exact match return it
        exact = [r for r in results if r['Distance'] == 0]
        if len(exact) == 1:
            return exact

    # If ther are more than 4 results and any are better than 6 return the first group of results
    if len(results) > 4:
        dist: list[tuple[int, list[SimpleResult]]] = []
        filtered_results: list[SimpleResult] = []
        for distance, group in itertools.groupby(results, key=lambda r: r['Distance']):
            dist.append((distance, list(group)))
        if aggressive_filtering and dist[0][0] < 6:
            for _, res in dist[:1]:
                filtered_results.extend(res)
            return filtered_results

    return results


def filter_results(results: list[Result], force_interactive=True, aggressive_filtering=False) -> list[Result]:
    ahash_results = sorted([r for r in results if r['Hash']['Kind'] == 'ahash'], key=lambda r: r['Distance'])
    dhash_results = sorted([r for r in results if r['Hash']['Kind'] == 'dhash'], key=lambda r: r['Distance'])
    phash_results = sorted([r for r in results if r['Hash']['Kind'] == 'phash'], key=lambda r: r['Distance'])
    hash_results = [phash_results, dhash_results, ahash_results]
    if not force_interactive:
        # If any of the hash types have a single exact match return it. Prefer phash for no particular reason
        for hashed_results in (phash_results, dhash_results, ahash_results):
            exact = [r for r in hashed_results if r['Distance'] == 0]
            if len(exact) == 1:
                return exact

    # If any of the hash types have more than 4 results and they have results better than 6 return the first group of results for each hash type
    for i, hashed_results in enumerate(hash_results):
        filtered_results: list[Result] = []
        if len(hashed_results) > 4:
            dist: list[tuple[int, list[Result]]] = []
            for distance, group in itertools.groupby(hashed_results, key=lambda r: r['Distance']):
                dist.append((distance, list(group)))

            if aggressive_filtering and dist[0][0] < 6:
                for _, res in dist[:1]:
                    filtered_results.extend(res)

        if filtered_results:
            hash_results[i] = filtered_results

    return list(itertools.chain(*hash_results))


def display_simple_results(md_results: list[tuple[int, GenericMetadata]], ca: comictaggerlib.cli.ComicArchive, force_interactive=True) -> GenericMetadata:
    filename_md = ca.metadata_from_filename(utils.Parser.COMICFN2DICT)
    if len(md_results) < 1:
        logger.warning('No results found for comic')
        raise SystemExit(4)
    if not force_interactive:
        if len(md_results) == 1 and md_results[0][0] <= 4:
            return md_results[0][1]
        series_match = []
        for score, md in md_results:
            if (
                score < 10
                and filename_md.series
                and md.series
                and utils.titles_match(filename_md.series, md.series)
                and IssueString(filename_md.issue).as_string() == IssueString(md.issue).as_string()
            ):
                series_match.append(md)
        if len(series_match) == 1:
            return series_match[0]

    md_results.sort(key=lambda r: (r[0], len(r[1].publisher or '')))
    for counter, r in enumerate(md_results, 1):
        print(
            '    {:2}. score: {} [{:15}] ({:02}/{:04}) - {} #{} - {}'.format(
                counter,
                r[0],
                r[1].publisher,
                r[1].month or 0,
                r[1].year or 0,
                r[1].series,
                r[1].issue,
                r[1].title,
            ),
        )
    while True:
        i = input(
            f'Please select a result to tag the comic with or "q" to quit: [1-{len(md_results)}] ',
        ).casefold()
        if (i.isdigit() and int(i) in range(1, len(md_results) + 1)):
            break
        if i == 'q':
            logger.warning('User quit without saving metadata')
            raise SystemExit(4)

    return md_results[int(i) - 1][1]


def display_results(md_results: list[tuple[int, Hash, GenericMetadata]], ca: comictaggerlib.cli.ComicArchive, force_interactive=True) -> GenericMetadata:
    filename_md = ca.metadata_from_filename(utils.Parser.COMICFN2DICT)
    if len(md_results) < 1:
        logger.warning('No results found for comic')
        raise SystemExit(4)
    if not force_interactive:
        if len(md_results) == 1 and md_results[0][0] <= 4:
            return md_results[0][2]
        series_match = []
        for score, hash, md in md_results:
            if (
                score < 10
                and filename_md.series
                and md.series
                and utils.titles_match(filename_md.series, md.series)
                and IssueString(filename_md.issue).as_string() == IssueString(md.issue).as_string()
            ):
                series_match.append(md)
        if len(series_match) == 1:
            return series_match[0]
    md_results.sort(key=lambda r: (r[0], len(r[2].publisher or ''), r[1]["Kind"]))
    for counter, r in enumerate(md_results, 1):
        print(
            '    {:2}. score: {} {}: {:064b} [{:15}] ({:02}/{:04}) - {} #{} - {}'.format(
                counter,
                r[0],
                r[1]["Kind"],
                r[1]["Hash"],
                r[2].publisher,
                r[2].month or 0,
                r[2].year or 0,
                r[2].series,
                r[2].issue,
                r[2].title,
            ),
        )
    while True:
        i = input(
            f'Please select a result to tag the comic with or "q" to quit: [1-{len(md_results)}] ',
        ).casefold()
        if (i.isdigit() and int(i) in range(1, len(md_results) + 1)):
            break
        if i == 'q':
            logger.warning('User quit without saving metadata')
            raise SystemExit(4)

    return md_results[int(i) - 1][2]


def fetch_full_issue_data(md: GenericMetadata, cv_api_key: str | None = None) -> GenericMetadata:
    cache_dir = pathlib.Path(appdirs.user_cache_dir('quick_tag'))
    cache_dir.mkdir(parents=True, exist_ok=True)
    cv = CV(f"quick_tag/{__version__}", cache_dir)
    cv.parse_settings({
        'comicvine_key': cv_api_key,
        'cv_use_series_start_as_volume': True,
    })
    return cv.fetch_comic_data(issue_id=md.issue_id)


def prepare_metadata(md: GenericMetadata, new_md: GenericMetadata, clear_tags: bool, auto_imprint: bool, remove_html_tables: bool) -> GenericMetadata:

    final_md = md.copy()
    if clear_tags:
        final_md = GenericMetadata()

    final_md.overlay(new_md, merge.Mode.OVERLAY, True)

    issue_id = ''
    if final_md.issue_id:
        issue_id = f" [Issue ID {final_md.issue_id}]"

    origin = ''
    if final_md.data_origin is not None:
        origin = f" using info from {final_md.data_origin.name}"
    notes = f"Tagged with quick_tag {__version__}{origin} on {datetime.now():%Y-%m-%d %H:%M:%S}.{issue_id}"

    if auto_imprint:
        final_md.fix_publisher()

    return final_md.replace(
        is_empty=False,
        notes=utils.combine_notes(final_md.notes, notes, 'Tagged with quick_tag'),
        description=cleanup_html(final_md.description, remove_html_tables),
    )


def main():
    manager = settngs.Manager('Simple comictagging script using ImageHash: https://pypi.org/project/ImageHash/')
    manager.add_group('runtime', settings)
    opts, _ = manager.parse_cmdline()
    url: utils.Url = opts['runtime']['url']
    max_hamming_distance: int = opts['runtime']['max']
    simple: bool = opts['runtime']['simple']

    ca = comicarchive.ComicArchive(opts['runtime']['comic_archive'])
    if not ca.seems_to_be_a_comic_archive():
        logger.error('Could not open %s as an archive', ca.path)
        raise SystemExit(1)

    try:
        tags = ca.read_tags('cr')
        cover_index = tags.get_cover_page_index_list()[0]
        cover_image = Image.open(BytesIO(ca.get_page(cover_index)))
    except Exception:
        logger.exception('Unable to read cover image from archive')
        raise SystemExit(2)
    print('Tagging: ', ca.path)

    print("hashing cover")
    phash = dhash = ahash = ''
    if HashType.AHASH in opts['runtime']['hash']:
        ahash = imagehash.average_hash(cover_image)
    if HashType.DHASH in opts['runtime']['hash']:
        dhash = imagehash.dhash(cover_image)
    if HashType.PHASH in opts['runtime']['hash']:
        phash = imagehash.phash(cover_image)

    print("Searching hashes")
    results = SearchHashes(url.url, simple, max_hamming_distance, str(ahash), str(dhash), str(phash), opts['runtime']['skip_non_exact'])

    print("Retrieving basic ComicVine data")
    if simple:
        filtered_results = filter_simple_results(cast(list[SimpleResult], results), opts['runtime']['force_interactive'], opts['runtime']['aggressive_filtering'])
        metadata_results = get_simple_results(filtered_results, opts['runtime']['cv_api_key'])
        chosen_result = display_simple_results(metadata_results, ca, opts['runtime']['force_interactive'])
    else:
        filtered_results = filter_results(cast(list[Result], results), opts['runtime']['force_interactive'], opts['runtime']['aggressive_filtering'])
        metadata_results = get_results(filtered_results, opts['runtime']['cv_api_key'])
        chosen_result = display_results(metadata_results, ca, opts['runtime']['force_interactive'])

    full_cv_md = fetch_full_issue_data(chosen_result, opts['runtime']['cv_api_key'])

    if ca.write_tags(prepare_metadata(tags, full_cv_md, clear_tags=False, auto_imprint=True, remove_html_tables=True), 'cr'):
        print(f'successfully saved metadata to {ca.path}')
        raise SystemExit(0)
    logger.error('Failed to save metadata to %s', ca.path)
    raise SystemExit(2)


if __name__ == '__main__':
    main()
