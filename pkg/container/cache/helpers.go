package cache

// ManifestFile creates Manifest filename to be requested from the cache server.
func ManifestFile(imageTag string) (string, error) {
	repoURL, imageTag := resolveImageTag(imageTag)

	image, tag, err := splitImageTag(imageTag)
	if err != nil {
		return "", err
	}

	return sanitizeURL(buildManifestURL(repoURL, image, tag)), nil
}

// BlobFile creates blob filename to be requested from the cache server.
func BlobFile(imageTag, digest string) (string, error) {
	repoURL, imageTag := resolveImageTag(imageTag)

	image, _, err := splitImageTag(imageTag)
	if err != nil {
		return "", err
	}

	return sanitizeURL(buildBlobURL(repoURL, image, digest)), nil
}
