import argparse
import logging
from typing import TypedDict
from urllib.parse import urljoin
from PIL import Image
import appdirs
from comicapi.genericmetadata import GenericMetadata
import pathlib, imagehash, requests
import settngs, comictaggerlib.cli
from io import BytesIO
from comicapi import comicarchive, merge

from datetime import datetime

from comicapi import utils
from comicapi.genericmetadata import GenericMetadata
from comictaggerlib import ctversion
from comictaggerlib.cbltransformer import CBLTransformer
from comictaggerlib.ctsettings.settngs_namespace import SettngsNS
from comictalker.talker_utils import cleanup_html

logger = logging.getLogger("quick_tag")

__version__ = '0.1'


class SimpleResult(TypedDict):
	Distance: int
	IDList: dict[str, list[str]]  # Mapping of domains (eg comicvine.gamespot.com) to IDs


def settings(manager: settngs.Manager):
	manager.add_setting("--url", '-u', default='https://comic-hasher.narnian.us', type=utils.parse_url, help='Website to use for searching cover hashes')
	manager.add_setting("--max","-m", default=8, type=int, help='Maximum score to allow. Lower score means more accurate')
	manager.add_setting("--simple", "-s", default=True, action=argparse.BooleanOptionalAction, help='Whether to retrieve simple results or full results')
	manager.add_setting("--force-interactive", "-f", default=True, action=argparse.BooleanOptionalAction, help='When not set will automatically tag comics that have a single match with a score of 4 or lower')
	manager.add_setting("--cv-api-key", "-c")
	manager.add_setting("comic_archive", type=pathlib.Path)

def SearchHashes(url: str, simple: bool, max: int, ahash: str, dhash: str, phash: str) -> list[SimpleResult]:
	resp = requests.get(urljoin(url, '/match_cover_hash'), {"simple": simple, "max": max, "ahash":ahash, "dhash": dhash, "phash": phash})
	if resp.status_code != 200:
		logger.error("bad response from server: %s", resp.text)
		raise SystemExit(3)
	return resp.json()


def get_simple_results(results: list[SimpleResult], cv_api_key: str | None = None) -> list[tuple[int, GenericMetadata]]:
	from comictalker.talkers.comicvine import ComicVineTalker
	cache_dir = pathlib.Path(appdirs.user_cache_dir('quick_tag'))
	cache_dir.mkdir(parents=True, exist_ok=True)
	cv = ComicVineTalker(f"quick_tag/{__version__}",cache_dir)
	cv.parse_settings({"comicvine_key": cv_api_key})
	md_results: list[tuple[int, GenericMetadata]] = []
	results.sort(key=lambda r: r['Distance'])
	for result in results:
		for cv_id in result['IDList']['comicvine.gamespot.com']:
			md_results.append((result['Distance'], cv.fetch_comic_data(issue_id=cv_id)))
	return md_results


def display_simple_results(md_results: list[tuple[int, GenericMetadata]], force_interactive=True) -> GenericMetadata:
	if len(md_results) == 1 and md_results[0][0] <= 4 and not force_interactive:
		return md_results[0][1]
	for counter, r in enumerate(md_results, 1):
		print(
			"    {}. {} #{} [{}] ({}/{}) - {} score: {}".format(
				counter,
				r[1].series,
				r[1].issue,
				r[1].publisher,
				r[1].month,
				r[1].year,
				r[1].title,
				r[0]
			),
		)
	while True:
		i = input(f'Please select a result to tag the comic with or "q" to quit: [1-{len(md_results)}] ').casefold()
		if (i.isdigit() and int(i) in range(1, len(md_results) + 1)):
			break
		if i == 'q':
			logger.warning("User quit without saving metadata")
			raise SystemExit(4)

	return md_results[int(i)-1][1]




def prepare_metadata(md: GenericMetadata, new_md: GenericMetadata, clear_tags: bool, auto_imprint: bool, remove_html_tables: bool) -> GenericMetadata:

    final_md = md.copy()
    if clear_tags:
        final_md = GenericMetadata()

    final_md.overlay(new_md, merge.Mode.OVERLAY, True)

    issue_id = ""
    if final_md.issue_id:
        issue_id = f" [Issue ID {final_md.issue_id}]"

    origin = ""
    if final_md.data_origin is not None:
        origin = f" using info from {final_md.data_origin.name}"
    notes = f"Tagged with quick_tag {__version__}{origin} on {datetime.now():%Y-%m-%d %H:%M:%S}.{issue_id}"

    if auto_imprint:
        final_md.fix_publisher()

    return final_md.replace(
        is_empty=False,
        notes=utils.combine_notes(final_md.notes, notes, "Tagged with quick_tag"),
        description=cleanup_html(final_md.description, remove_html_tables) or None,
    )
def main():
	manager = settngs.Manager('Simple comictagging script using ImageHash: https://pypi.org/project/ImageHash/')
	manager.add_group("runtime", settings)
	opts,_ = manager.parse_cmdline()
	url: utils.Url = opts['runtime']['url']
	print(url)
	max_hamming_distance: int = opts['runtime']['max']
	simple: bool = opts['runtime']['simple']
	if not simple:
		logger.error("Full results not implemented yet")
		raise SystemExit(1)
	ca = comicarchive.ComicArchive(opts['runtime']['comic_archive'])
	if not ca.seems_to_be_a_comic_archive():
		logger.error("Could not open %s as an archive", ca.path)
		raise SystemExit(1)

	try:
		tags = ca.read_tags('cr')
		cover_index = tags.get_cover_page_index_list()[0]
		cover_image = Image.open(BytesIO(ca.get_page(cover_index)))
	except Exception:
		logger.exception("Unable to read cover image from archive")
		raise SystemExit(2)
	print('Tagging: ', ca.path)

	ahash = imagehash.average_hash(cover_image)
	dhash = imagehash.dhash(cover_image)
	phash = imagehash.phash(cover_image)

	results = SearchHashes(url.url, simple,max_hamming_distance,str(ahash),str(dhash),str(phash))
	print(results)
	if simple:
		metadata_results = get_simple_results(results, opts['runtime']['cv_api_key'])
		chosen_result = display_simple_results(metadata_results, opts['runtime']['force_interactive'])
	else:
		metadata_results = get_full_results(results)
		chosen_result = display_full_results(metadata_results)

	if ca.write_tags(prepare_metadata(GenericMetadata(), chosen_result, clear_tags=False, auto_imprint=True, remove_html_tables=True), 'cr'):
		print(f'successfully saved metadata to {ca.path}')
		raise SystemExit(0)
	logger.error("Failed to save metadata to %s", ca.path)
	raise SystemExit(2)



if __name__ == "__main__":
	main()
