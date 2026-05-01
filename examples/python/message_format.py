def format_message(salutation, name, runtime_version):
    return "{}, {} from Python {}.".format(
        salutation,
        name,
        runtime_version.base_version,
    )
