export class SignupValidationError extends Error {
    constructor(message) {
        super(message)
        this.name = 'SignupValidationError'
    }
}

const DISPOSABLE_EMAIL_DOMAINS = new Set([
    '10minutemail.com',
    'discard.email',
    'getnada.com',
    'guerrillamail.com',
    'guerrillamailblock.com',
    'maildrop.cc',
    'mailinator.com',
    'sharklasers.com',
    'temp-mail.org',
    'tempmail.com',
    'throwaway.email',
    'trashmail.com',
    'yopmail.com',
])

export const SIGNUP_MIN_PASSWORD_LENGTH = 6

function validatePersonName(name, fieldLabel) {
    const trimmed = name.trim()

    if (trimmed.length < 2 || trimmed.length > 40) {
        throw new SignupValidationError(`Invalid ${fieldLabel}`)
    }

    if (!/^[\p{L}][\p{L} '.-]*$/u.test(trimmed)) {
        throw new SignupValidationError(`Invalid ${fieldLabel}`)
    }

    if (!/[aeiouAEIOUyY]/i.test(trimmed)) {
        throw new SignupValidationError(`Invalid ${fieldLabel}`)
    }

    if (
        !/\s/u.test(trimmed)
        && trimmed.length >= 12
        && /[A-Z]/.test(trimmed)
        && /[a-z]/.test(trimmed)
    ) {
        throw new SignupValidationError(`Invalid ${fieldLabel}`)
    }
}

function resolveNames({ first, last, name }) {
    let firstName = typeof first === 'string' ? first.trim() : ''
    let lastName = typeof last === 'string' ? last.trim() : ''

    if (!firstName && !lastName && typeof name === 'string') {
        const trimmed = name.trim()
        if (trimmed) {
            const parts = trimmed.split(/\s+/)
            firstName = parts.shift() || ''
            lastName = parts.length ? parts.join(' ') : ''
        }
    }

    return { firstName, lastName }
}

/**
 * Validate and normalize register payload. Throws SignupValidationError on failure.
 */
export function validateSignupInput(input, { minPasswordLength = SIGNUP_MIN_PASSWORD_LENGTH } = {}) {
    const { email, password, company } = input ?? {}
    const { firstName, lastName } = resolveNames(input)

    if (!email || typeof email !== 'string') {
        throw new SignupValidationError('Email is required')
    }

    if (!password || typeof password !== 'string') {
        throw new SignupValidationError('Password is required')
    }

    if (!firstName || !lastName) {
        throw new SignupValidationError('First and last name are required')
    }

    validatePersonName(firstName, 'first name')
    validatePersonName(lastName, 'last name')

    const normalizedEmail = email.toLowerCase().trim()

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
        throw new SignupValidationError('Invalid email address')
    }

    const domain = normalizedEmail.split('@')[1]
    if (DISPOSABLE_EMAIL_DOMAINS.has(domain)) {
        throw new SignupValidationError('Email address not allowed')
    }

    if (password.length < minPasswordLength) {
        throw new SignupValidationError(
            `Password must be at least ${minPasswordLength} characters`,
        )
    }

    const normalizedCompany = typeof company === 'string' ? company.trim() : ''
    if (!normalizedCompany || normalizedCompany.length < 2) {
        throw new SignupValidationError('Company is required')
    }

    return {
        email: normalizedEmail,
        password,
        first: firstName,
        last: lastName,
        company: normalizedCompany,
    }
}
