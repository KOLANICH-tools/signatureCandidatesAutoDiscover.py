#!/usr/bin/env python3

import glob
import re
import struct
import typing
from ast import literal_eval
from binascii import b2a_hex
from collections import defaultdict
from pathlib import Path
from warnings import warn

import hexdump
from fsutilz import MMap
from plumbum import cli

warn("We have moved from M$ GitHub to https://codeberg.org/KOLANICH-tools/signatureCandidatesAutoDiscover.py , read why on https://codeberg.org/KOLANICH/Fuck-GuanTEEnomo .")

try:
	raise ImportError("hyperscan-based scanning doesn't work for now")
	from enum import IntEnum

	import hyperscan as hs
except ImportError:
	from warnings import warn

	# warn("Install hyperscan for significant speedup") # not functional by now, no acceleration!
	hs = None
else:
	HSErrorCode = IntEnum("HSErrorCode", {el[3:-6]: getattr(hs, el) for el in dir(hs) if el.endswith("_ERROR")})
	HSFlag = IntEnum("HSFlag", {el[8:]: getattr(hs, el) for el in dir(hs) if el.startswith("HS_FLAG_")})
	HSMode = IntEnum("HSMode", {el[8:]: getattr(hs, el) for el in dir(hs) if el.startswith("HS_MODE_")})

	hsMode = HSMode.BLOCK
	# hsRxFlags = HSFlag.SINGLEMATCH | HSFlag.SOM_LEFTMOST | HSFlag.ALLOWEMPTY | HSFlag.DOTALL | HSFlag.MULTILINE
	hsRxFlags = HSFlag.SOM_LEFTMOST | HSFlag.ALLOWEMPTY | HSFlag.DOTALL
	hsLiteralFlags = HSFlag.SINGLEMATCH


hexNumberRxSrc = "(-?0x[\\da-fA-F+]{8})"
decNumberRxSrc = "(-?\\d+)"
llvmVarRxSrc = "%\\d+"
llvmJumpTargetRxSrc = "!\\d+"
llvmInstrRxSrc = "(?:ne|eq)"

x86OperandRxSrc = "(?:dword\\s+ptr\\s+\\[[^\\]+]\\]|eax|rax)"
x86InstrRxSrc = "(?:cmp|mov|movabs)"

signsRegExps = {
	"c": (
		hexNumberRxSrc + "\\s*==",
		"=\\s*" + hexNumberRxSrc,
		"case\\s+" + hexNumberRxSrc + "\\s*:",
	),
	"dsm": (x86InstrRxSrc + " " + x86OperandRxSrc + ", " + hexNumberRxSrc,),
	"ll": (
		"store\\s+i32\\s+" + decNumberRxSrc + ",",
		llvmVarRxSrc + "\\s*=\\s*icmp\\s+" + llvmInstrRxSrc + "\\s+i32\\s+" + llvmVarRxSrc + ",\\s*" + decNumberRxSrc + ",\\s*!insn\\.addr\\s+" + llvmJumpTargetRxSrc,
		"global\\s+i32\\s+" + decNumberRxSrc,
		"i32\\s+" + decNumberRxSrc + ",\\s*label\\s+%\w+",
		"constant\\s+i32\\s+" + decNumberRxSrc,
	),
}

if hs:

	def genHyperscanDbsForRegExprs(signsRegExps):
		res = {}
		for k, v in signsRegExps.items():
			print("k", k, "v", v)
			hsMode = HSMode.BLOCK  # | HSMode.SOM_HORIZON_SMALL
			rxd = hs.Database(mode=hsMode)
			rxd.compile(tuple(el.encode("ascii") for el in v), tuple(range(len(v))), flags=[hsRxFlags] * len(v))
			res[k] = (rxd, tuple(re.compile(el) for el in v))
		print("Regs db compiled")
		return res

	signsRegExps = genHyperscanDbsForRegExprs(signsRegExps)
else:
	signsRegExps = {k: tuple(re.compile(el) for el in v) for k, v in signsRegExps.items()}


class SignsDiscoverer:
	__slots__ = ("signs",)

	def __init__(self):
		self.signs = set()

	def scanSinglePath(self, p: Path, rxs):
		raise NotImplementedError

	def scanFiles(self, files):
		for p in files:
			ext = p.suffix[1:].lower()
			rxs = signsRegExps.get(ext, None)
			if rxs:
				self.scanSinglePath(p, rxs)

	def onFind(self, foundStr):
		i = literal_eval(foundStr)
		if i >= 0:
			s = struct.pack("<I", i)
		else:
			s = struct.pack("<i", i)
		if not isSigDisqualifiedBasedOnItsProperties(s):
			self.signs.add(s)


codeScanningBackendCtor = None
if hs:
	class HyperScanSignaturesDiscoverer(SignsDiscoverer):
		__slots__ = ()

		def scanSinglePath(self, p: Path, rxs):
			hsRxs, rxs = rxs
			with MMap(p) as f:

				def matchesHandler(iD, start, stop, flags, ctx):
					s = f[start:stop].decode("ascii")
					m = rxs[iD].match(s)
					self.onFind(m.group(1))

				hsRxs.scan(bytes(f), matchesHandler)

		codeScanningBackendCtor = HyperScanSignaturesDiscoverer

else:

	class RegExpSignaturesDiscoverer(SignsDiscoverer):
		__slots__ = ()

		def scanSinglePath(self, p: Path, rxs):
			with p.open("rt") as f:
				for l in f:
					for rx in rxs:
						m = rx.search(l)
						if m:
							self.onFind(m.group(1))

	codeScanningBackendCtor = RegExpSignaturesDiscoverer


def discoverSignsFromDecompiledCodeFiles(files: typing.Iterable[Path]):
	d = codeScanningBackendCtor()
	d.scanFiles(files)
	return sorted(d.signs)


def escapeBytes(b: bytes) -> bytes:
	"""Converts bytes object into bytes regular expression"""

	return b"".join([b"\\x" + b2a_hex(bytes((el,))) for el in b"aaaa"])


if hs:
	raise NotImplementedError("Scanning doesn't works for now IDK why, no maches found")
	def countSignsInFiles(signs, files: typing.Iterable[Path]):
		d = hs.Database(mode=hsMode)
		d.compile(tuple(escapeBytes(s) for s in signs), tuple(struct.unpack("<I", s)[0] for s in signs), flags=[hsLiteralFlags] * len(signs), literal=True)

		presentSigs = defaultdict(int)

		def matchesHandler(iD, start, stop, flags, ctx):
			print(iD, start, stop, flags, ctx)
			presentSigs[struct.pack("<I", iD)] += 1

		for p in sorted(files):
			with MMap(p) as f:
				d.scan(bytes(f), matchesHandler)
		return presentSigs
else:
	def countSignsInFiles(signs, files: typing.Iterable[Path]):
		presentSigs = defaultdict(int)
		for p in sorted(files):
			with MMap(p) as d:
				for s in signs:
					if d.find(s) > -1:
						presentSigs[s] += 1
		return presentSigs


def _sortSigs(countedSigsItems):
	return sorted(countedSigsItems, key=lambda x: -x[1])


def sortSigs(countedSigs):
	return dict(_sortSigs(countedSigs.items()))


sigBasedDisqualifyingFilters = (
	lambda sig: sig.startswith(b"\x00\x00"),
	lambda sig: sig.startswith(b"\xFF\xFF"),
	lambda sig: sig.endswith(b"\x00\x00"),
	lambda sig: sig.endswith(b"\xFF\xFF"),
	lambda sig: sig[1] == 0 and sig[3] == 0,
	lambda sig: sig[0] == 0 and sig[2] == 0,
)


def isSigDisqualifiedBasedOnItsProperties(sig: bytes):
	for tester in sigBasedDisqualifyingFilters:
		if tester(sig):
			return True
	return False


disqualifyingFilters = (lambda sig, count: count < 2, lambda sig, count: isSigDisqualifiedBasedOnItsProperties(sig))


def isSigDisqualified(sig: bytes, count: int):
	for tester in disqualifyingFilters:
		if tester(sig, count):
			return True
	return False


def _filterSigs(countedSigsItems):
	for sig, count in countedSigsItems:
		if isSigDisqualified(sig, count):
			continue

		yield sig, count


def filterSigs(countedSigs):
	return dict(_filterSigs(countedSigs.items()))


def genReportStringForSig(sig: bytes, count: int):
	reportStr = hexdump.dump(sig) + " " + repr(sig) + " " + repr(count) + " "
	i = struct.unpack("<i", sig)[0]
	reportStr += repr(i) + " " + hex(i)

	if i < 0:
		i = struct.unpack("<I", sig)[0]
		reportStr += " " + repr(i) + " " + hex(i)

	return reportStr


def _reportSigs(sigCountItems):
	for el in sigCountItems:
		print(genReportStringForSig(*el))


def reportSigs(countedSigs):
	return _reportSigs(countedSigs.items())


class CLI(cli.Application):
	def main(self, samplesGlob: str):
		sampleFiles = sorted(Path(el) for el in glob.glob(samplesGlob))
		sourceFiles = []
		for el in signsRegExps:
			sourceFiles.extend(Path(".").glob("*." + el))
		sourceFiles.sort()
		print(sampleFiles)
		print(sourceFiles)
		signs = discoverSignsFromDecompiledCodeFiles(sourceFiles)
		print("Discovered potential signatures from decompilation results:", len(signs))

		countedSigs = countSignsInFiles(signs, sampleFiles)
		countedSigs = sortSigs(countedSigs)
		countedSigs = filterSigs(countedSigs)
		print(countedSigs)

		_reportSigs(countedSigs.items())


if __name__ == "__main__":
	CLI.run()
