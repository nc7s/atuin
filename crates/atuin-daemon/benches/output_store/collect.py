#!/usr/bin/env python3
"""Collect real, public-workspace command output for the output-store benchmark."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shlex
import shutil
import subprocess
from datetime import datetime, timezone

KINDS = ('silent', 'short', 'listing', 'search', 'git', 'build', 'test', 'help', 'data')
PATTERNS = (
	'pub fn', 'async fn', 'struct ', 'enum ', 'impl ', 'Result<', 'Error',
	'assert', 'unwrap', 'TODO', 'Serialize', 'use std::', '#\\[test\\]',
	'#\\[cfg', 'unsafe', 'fn new', 'match ', 'where', 'Display', 'Option<',
)


def assignments(values):
	result = {}
	for value in values:
		name, path = value.split('=', 1)
		if not re.fullmatch(r'[a-z0-9_-]+', name):
			raise ValueError(f'invalid project name: {name}')
		result[name] = Path(path).resolve()
	return result


class Collector:
	def __init__(self, args):
		self.output = args.output.resolve()
		self.projects = assignments(args.project)
		self.build_projects = assignments(args.build_project)
		self.network_args = ['--offline'] if args.offline else []
		self.records = []
		self.sources = []
		self.environment = dict(os.environ, CARGO_TERM_COLOR='never', NO_COLOR='1', LC_ALL='C.UTF-8')
		self.environment.update(CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_INCREMENTAL='0')
		self.environment['CARGO_BUILD_JOBS'] = '4'
		self.environment['CARGO_TARGET_DIR'] = str(args.target.resolve())
		self.replacements = [(str(args.target.resolve()), '/workspace/target')]
		for name, path in self.projects.items():
			self.replacements.append((str(path), f'/workspace/{name}'))
		for name, path in self.build_projects.items():
			self.replacements.append((str(path), f'/workspace/{name}'))
		self.replacements.extend([(str(Path.home() / '.cargo'), '/cargo'), (str(Path.home()), '/home/user')])
		self.replacements.sort(key=lambda pair: len(pair[0]), reverse=True)
		self.output.mkdir(parents=True, exist_ok=False)
		(self.output / 'outputs').mkdir()
		(self.output / 'licenses').mkdir()

	def capture(self, project, kind, command, *, workspace=None, accepted=(0, 1)):
		root = workspace or self.projects[project]
		result = subprocess.run(command, cwd=root, env=self.environment, stdout=subprocess.PIPE,
			stderr=subprocess.STDOUT, timeout=300, check=False)
		if result.returncode not in accepted:
			raise RuntimeError(f'{project}: {shlex.join(command)} exited {result.returncode}:\n'
				+ result.stdout.decode('utf-8', errors='replace')[-4000:])
		text = result.stdout.decode('utf-8', errors='replace')
		for source, replacement in self.replacements:
			text = text.replace(source, replacement)
		# Pipe capture avoids terminal cursor updates; normalize any remaining carriage returns.
		text = text.replace('\r\n', '\n').replace('\r', '\n')
		data = text.encode('utf-8')
		digest = hashlib.sha256(data).hexdigest()
		path = f'outputs/{digest}.txt'
		if not (self.output / path).exists():
			(self.output / path).write_bytes(data)
		self.records.append(dict(project=project, kind=kind, command=command,
			exit_code=result.returncode, output=path, bytes=len(data)))
		if len(self.records) % 100 == 0 or kind in ('build', 'test'):
			print(f'{len(self.records):4}: {project}: {shlex.join(command)} ({len(data)} bytes)', flush=True)

	def source(self, project):
		root = self.projects[project]
		manifest = (root / 'Cargo.toml').read_text()
		version = re.search(r'^version\s*=\s*"([^"]+)"', manifest, re.MULTILINE)
		if (root / '.git').exists():
			revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
			files = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
		else:
			revision = version.group(1) if version else 'unknown'
			files = [str(path.relative_to(root)) for path in root.rglob('*') if path.is_file()]
		self.sources.append(dict(project=project, revision=revision,
			build_workspace_differs=root != self.build_projects.get(project, root)))
		for license_file in root.glob('LICENSE*'):
			if license_file.is_file():
				shutil.copyfile(license_file, self.output / 'licenses' / f'{project}-{license_file.name}')
		return sorted(file for file in files if file.endswith('.rs')
			and not any(part in Path(file).parts for part in ('target', 'vendor', '.git')))

	def development(self, project, packages):
		workspace = self.build_projects.get(project, self.projects[project])
		for package in packages:
			selection = ['-p', package] if package else []
			for operation in ('check', 'build'):
				self.capture(project, 'build', ['cargo', operation, *self.network_args, '--lib', *selection],
					workspace=workspace, accepted=(0,))
			self.capture(project, 'test', ['cargo', 'test', *self.network_args, '--lib', *selection],
				workspace=workspace, accepted=(0,))
			self.capture(project, 'data', ['cargo', 'tree', *self.network_args, *selection], workspace=workspace, accepted=(0,))
		self.capture(project, 'data', ['cargo', 'metadata', *self.network_args, '--no-deps', '--format-version', '1'],
			workspace=workspace, accepted=(0,))

	def daily_commands(self, project, files):
		root = self.projects[project]
		self.capture(project, 'silent', ['test', '-f', 'Cargo.toml'])
		self.capture(project, 'silent', ['test', '-d', 'src'])
		self.capture(project, 'short', ['pwd'])
		self.capture(project, 'short', ['cargo', '--version'])
		self.capture(project, 'listing', ['ls', '-lh'])
		self.capture(project, 'data', ['sha256sum', 'Cargo.toml'])
		self.capture(project, 'help', ['cargo', '--help'])
		self.capture(project, 'help', ['rustc', '--help'])
		self.capture(project, 'help', ['rg', '--help'])
		directories = sorted({str(Path(file).parent) for file in files})
		for directory in random.Random(42).sample(directories, min(30, len(directories))):
			self.capture(project, 'listing', ['ls', '-lh', directory])
			self.capture(project, 'data', ['du', '-sh', directory])
		for index, file in enumerate(random.Random(43).sample(files, min(120, len(files)))):
			self.capture(project, 'short', ['wc', '-l', file])
			self.capture(project, 'data', ['head', '-n', str((20, 60, 160, 400)[index % 4]), file])
			self.capture(project, 'search', ['rg', '-n', '-m', str((5, 20, 80)[index % 3]),
				'(pub |fn |struct |enum |impl |assert|Error)', file])
		scopes = [directory for directory in ('src', 'tests', 'crates/atuin-client/src',
		'crates/atuin-daemon/src', 'crates/atuin-common/src') if (root / directory).is_dir()]
		for scope in scopes:
			for pattern in PATTERNS:
				self.capture(project, 'search', ['rg', '-n', '-m', '8', '-g', '*.rs', pattern, scope])
			self.capture(project, 'listing', ['find', scope, '-type', 'f', '-name', '*.rs'])
		if (root / '.git').exists():
			self.git_commands(project)

	def git_commands(self, project):
		for count in (1, 5, 10, 20, 50, 100):
			self.capture(project, 'git', ['git', 'log', f'-{count}', '--format=%h %s', '--', 'crates'])
			self.capture(project, 'git', ['git', 'log', f'-{count}', '--stat', '--format=%h %s', '--', 'crates'])
		for index in range(40):
			self.capture(project, 'git', ['git', 'show', '--format=%h %s', '--stat', f'HEAD~{index}', '--', 'crates'])
			self.capture(project, 'git', ['git', 'diff', '--stat', f'HEAD~{index + 1}', 'HEAD', '--', 'crates'])
		self.capture(project, 'git', ['git', 'status', '--short', '--untracked-files=no'])
		self.capture(project, 'git', ['git', 'diff', '--numstat', '--', 'crates'])

	def finish(self):
		present = {record['kind'] for record in self.records}
		if missing := set(KINDS) - present:
			raise RuntimeError(f'corpus lacks categories: {missing}')
		manifest = dict(format_version=1, captured_at=datetime.now(timezone.utc).isoformat(),
			sources=self.sources, normalization=('UTF-8 replacement decoding, absolute workspace/home paths, '
				'CR to LF; no content templates'),
			records=self.records)
		(self.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
		print(f'{len(self.records)} commands, {len(set(record["output"] for record in self.records))} distinct outputs')


def main():
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument('--project', action='append', required=True, metavar='NAME=PATH')
	parser.add_argument('--build-project', action='append', default=[], metavar='NAME=PATH')
	parser.add_argument('--build', action='append', help='Project to build/test; omit to build all projects')
	parser.add_argument('--offline', action='store_true', help='Use only cached Cargo dependencies')
	parser.add_argument('--target', required=True, type=Path)
	parser.add_argument('--output', required=True, type=Path)
	args = parser.parse_args()
	collector = Collector(args)
	for project in collector.projects:
		files = collector.source(project)
		packages = ['atuin-common', 'atuin-domain', 'atuin-history', 'atuin-daemon'] if project == 'atuin' else [None]
		if args.build is None or project in args.build:
			collector.development(project, packages)
		collector.daily_commands(project, files)
	collector.finish()


if __name__ == '__main__':
	main()
