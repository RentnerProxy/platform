// A release has two catalog entries. The native publication test measures the
// emitted files and reserves capacity for the complete 1,000-entry catalog.
export const maximumRepositoryEntries = 1000
export const maximumRepositoryFiles = 32768

export const maximumCandidateBundleFiles = 4096
// The assessed bundle retains the candidate manifest and adds the image evidence,
// the binding, and a new manifest.
export const maximumAssessedBundleFiles = maximumCandidateBundleFiles + 3
