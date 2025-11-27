import { useEffect } from 'react'

function Toast({ message, type = 'info', onClose }) {
  useEffect(() => {
    const timer = setTimeout(() => {
      onClose()
    }, 5000)

    return () => clearTimeout(timer)
  }, [onClose])

  const styles = {
    success: {
      bg: 'bg-green-500 bg-opacity-20 border-green-500',
      icon: 'text-green-400',
      iconPath: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z'
    },
    error: {
      bg: 'bg-red-500 bg-opacity-20 border-red-500',
      icon: 'text-red-400',
      iconPath: 'M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z'
    },
    warning: {
      bg: 'bg-yellow-500 bg-opacity-20 border-yellow-500',
      icon: 'text-yellow-400',
      iconPath: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z'
    },
    info: {
      bg: 'bg-primary-500 bg-opacity-20 border-primary-500',
      icon: 'text-primary-400',
      iconPath: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z'
    }
  }

  const style = styles[type] || styles.info

  return (
    <div className={`${style.bg} border backdrop-blur-md rounded-lg shadow-2xl p-4 w-full sm:min-w-[320px] sm:max-w-md max-w-sm animate-slideIn`}>
      <div className="flex items-start gap-3">
        <svg className={`w-6 h-6 ${style.icon} flex-shrink-0 mt-0.5`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={style.iconPath} />
        </svg>
        <div className="flex-1">
          <p className="text-white text-sm leading-relaxed">{message}</p>
        </div>
        <button
          onClick={onClose}
          className="text-gray-400 hover:text-white transition-colors flex-shrink-0"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>
      
      {/* Progress bar */}
      <div className="mt-3 h-1 bg-gray-900 bg-opacity-30 rounded-full overflow-hidden">
        <div className={`h-full ${style.icon.replace('text-', 'bg-')} animate-shrink`}></div>
      </div>
    </div>
  )
}

export default Toast

