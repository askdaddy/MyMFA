export class OtpError extends Error {
  override name = 'OtpError'
}

export class Base32DecodeError extends OtpError {
  override name = 'Base32DecodeError'
}

export class OtpConfigError extends OtpError {
  override name = 'OtpConfigError'
}
