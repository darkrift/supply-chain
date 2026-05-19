"""Utils to validate [purl](https://github.com/package-url/purl-spec)s."""

load("@purl_type_validation//:validation.bzl", "validate_type")
load("//purl/private/strings:strings.bzl", "strings")

visibility([
    "//purl/private",
])

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

    return validate_type(
        type = type,
        namespace = namespace,
        name = name,
        version = version,
        qualifiers = qualifiers,
        subpath = subpath,
    )

def is_valid_type(type):
    if not type:
        return False

    first = strings.bytes.from_string(type[0])[0]
    if not strings.ascii.is_alpha(first):
        return False

    for c in strings.bytes.from_string(type):
        if strings.ascii.is_alphanumeric(c):
            continue
        if c in [45, 46]:  # '-', '.'
            continue
        return False

    return True
