export const RELIABILITY_FIXTURE_SOURCE_PATHS = [
    'scripts/runtime-reliability/fixture.ts',
    'scripts/runtime-reliability/fixture-core.ts',
    'scripts/runtime-reliability/fixture-context.ts',
    'scripts/runtime-reliability/fixture.validation.ts',
    'scripts/lib/request-context.ts',
] as const

export const RELIABILITY_FIXTURE_ARCHIVE_DIRECTORIES = ['web/src', 'core/src'] as const

export const RELIABILITY_FIXTURE_ARCHIVE_PATHS = [
    ...RELIABILITY_FIXTURE_ARCHIVE_DIRECTORIES,
    'tsconfig.json',
    'package.json',
    'bun.lock',
] as const
