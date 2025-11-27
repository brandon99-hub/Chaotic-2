import { useMemo } from 'react'

function PasswordStrength({ password }) {
  const strength = useMemo(() => {
    if (!password) return { score: 0, label: '', color: '' }

    let score = 0
    const checks = {
      length: password.length >= 8,
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      number: /[0-9]/.test(password),
      special: /[^A-Za-z0-9]/.test(password),
      longLength: password.length >= 12
    }

    // Calculate score
    if (checks.length) score += 1
    if (checks.lowercase) score += 1
    if (checks.uppercase) score += 1
    if (checks.number) score += 1
    if (checks.special) score += 1
    if (checks.longLength) score += 1

    // Determine strength level
    if (score <= 2) {
      return { score, label: 'Weak', color: 'red', percentage: 33, checks }
    } else if (score <= 4) {
      return { score, label: 'Medium', color: 'yellow', percentage: 66, checks }
    } else {
      return { score, label: 'Strong', color: 'green', percentage: 100, checks }
    }
  }, [password])

  if (!password) return null

  const colorClasses = {
    red: {
      bg: 'bg-red-500',
      border: 'border-red-500',
      text: 'text-red-400'
    },
    yellow: {
      bg: 'bg-yellow-500',
      border: 'border-yellow-500',
      text: 'text-yellow-400'
    },
    green: {
      bg: 'bg-green-500',
      border: 'border-green-500',
      text: 'text-green-400'
    }
  }

  const colors = colorClasses[strength.color]

  return (
    <div className="mt-3">
      {/* Strength bar */}
      <div className="flex items-center gap-2 mb-2">
        <div className="flex-1 h-2 bg-gray-900 bg-opacity-50 rounded-full overflow-hidden">
          <div 
            className={`h-full ${colors.bg} transition-all duration-300`}
            style={{ width: `${strength.percentage}%` }}
          ></div>
        </div>
        <span className={`text-xs font-semibold ${colors.text} min-w-[60px] text-right`}>
          {strength.label}
        </span>
      </div>

      {/* Requirements checklist */}
      <div className="space-y-1">
        <div className="flex items-center gap-2 text-xs">
          <CheckIcon checked={strength.checks.length} />
          <span className={strength.checks.length ? 'text-green-400' : 'text-gray-500'}>
            At least 8 characters
          </span>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <CheckIcon checked={strength.checks.uppercase && strength.checks.lowercase} />
          <span className={(strength.checks.uppercase && strength.checks.lowercase) ? 'text-green-400' : 'text-gray-500'}>
            Upper and lowercase letters
          </span>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <CheckIcon checked={strength.checks.number} />
          <span className={strength.checks.number ? 'text-green-400' : 'text-gray-500'}>
            At least one number
          </span>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <CheckIcon checked={strength.checks.special} />
          <span className={strength.checks.special ? 'text-green-400' : 'text-gray-500'}>
            Special character (!@#$%^&*)
          </span>
        </div>
      </div>

      {/* Recommendation */}
      {strength.score <= 2 && (
        <div className="mt-2 p-2 bg-red-500 bg-opacity-10 border border-red-500 border-opacity-30 rounded text-xs text-red-300">
          <strong>⚠️ Weak password:</strong> Add more character types for better security.
        </div>
      )}
      {strength.score >= 5 && (
        <div className="mt-2 p-2 bg-green-500 bg-opacity-10 border border-green-500 border-opacity-30 rounded text-xs text-green-300">
          <strong>✓ Strong password:</strong> Your password is secure!
        </div>
      )}
    </div>
  )
}

function CheckIcon({ checked }) {
  return (
    <div className={`w-4 h-4 rounded-full flex items-center justify-center ${checked ? 'bg-green-500 bg-opacity-20 border border-green-500' : 'bg-gray-900 bg-opacity-50 border border-gray-700'}`}>
      {checked ? (
        <svg className="w-3 h-3 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
        </svg>
      ) : (
        <svg className="w-2 h-2 text-gray-600" fill="currentColor" viewBox="0 0 8 8">
          <circle cx="4" cy="4" r="2" />
        </svg>
      )}
    </div>
  )
}

export default PasswordStrength

