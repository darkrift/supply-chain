"""Utils to validate [purl](https://github.com/package-url/purl-spec)s."""

load("//purl/private/strings:strings.bzl", "strings")
load("//purl/private/validation:cpan.bzl", "validate_cpan")
load("//purl/private/validation:julia.bzl", "validate_julia")
load("//purl/private/validation:otp.bzl", "validate_otp")
load("//purl/private/validation:swift.bzl", "validate_swift")
load("//purl/private/validation:vscode_extension.bzl", "validate_vscode_extension")

visibility([
    "//purl/private",
])

_validators = {
    "cpan": validate_cpan,
    "julia": validate_julia,
    "otp": validate_otp,
    "swift": validate_swift,
    "vscode-extension": validate_vscode_extension,
}

def validate(
        *,
        type = None,
        namespace = None,
        name = None,
        version = None,
        qualifiers = {},
        subpath = None):
    # Spec §5: Validate required fields are present.
    if not type:
        return "Mandatory property 'type' not set"
    if not name:
        return "Mandatory property 'name' not set"

    type = type.lower()

    for i, c in enumerate(strings.bytes.from_string(type)):
        if strings.ascii.is_alphanumeric(c):
            if i == 0 and not strings.ascii.is_alpha(c):
                return "PURL type must start with an ASCII letter"
            continue
        elif c == 46 or c == 45 or c == 95:  # . - _
            continue

        return "PURL type {} contains illegal character {}".format(type, c)

    if type == "cpan":
        if not namespace:
            return "CPAN PURLs require a namespace"
        if "::" in name:
            return "CPAN PURL names must be distribution names, not module names"
    elif type == "vscode-extension":
        if not namespace:
            return "VS Code Extension PURLs require a namespace"
    elif type == "julia":
        if not qualifiers or not qualifiers.get("uuid"):
            return "Julia PURLs require a uuid qualifier"
    elif type == "chrome-extension":
        if len(name) != 32:
            return "Chrome extension IDs must be 32 characters"
        for c in name.elems():
            if c < "a" or c > "p":
                return "Chrome extension IDs may only contain characters a-p"
        if version:
            segments = version.split(".")
            if len(segments) > 4:
                return "Chrome extension versions may have at most four segments"
            for segment in segments:
                if not segment:
                    return "Chrome extension version segments must not be empty"
                for c in strings.bytes.from_string(segment):
                    if not strings.ascii.is_alphanumeric(c) or strings.ascii.is_alpha(c):
                        return "Chrome extension version segments must be numeric"
    elif type == "swift":
        if not namespace or "/" not in namespace:
            return "Swift PURLs require a repository host and owner namespace"
    elif type == "otp":
        if namespace:
            return "OTP PURLs must not contain a namespace"

    if qualifiers:
        for key, value in qualifiers.items():
            # 5.6.6

            if len(key) < 1:
                return "Qualifier key must not be empty string"

            # The key shall be composed only of lowercase ASCII letters and numbers,
            # period '.', dash '-' and underscore '_'.
            for c in strings.bytes.from_string(key):
                if strings.ascii.is_alphanumeric(c):
                    continue
                elif c == 46:  # .
                    continue
                elif c == 45:  # -
                    continue
                elif c == 95:  # _
                    continue

                return "Qualifier key {} contains illegal character {}".format(key, c)

            # A key shall start with an ASCII letter.
            for c in strings.bytes.from_string(key[0]):
                if strings.ascii.is_alpha(c):
                    continue

                return "Qualifier key {} does not start with ASCII letter, got {}".format(key, c)

    validator = _validators.get(type)
    if not validator:
        return None

    return validator(
        type = type,
        namespace = namespace,
        name = name,
        version = version,
        qualifiers = qualifiers,
        subpath = subpath,
    )
