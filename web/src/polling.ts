// every runs fn every ms while the page is visible, and returns what stops it. A tab in the background asks the server
// nothing: when it's shown again, fn runs at once if a turn was missed, then every ms again.
export function every(ms: number, fn: () => unknown): () => void {
  let missed = false
  const tick = () => {
    if (document.hidden) {
      missed = true
      return
    }
    fn()
  }
  let timer = window.setInterval(tick, ms)
  const shown = () => {
    if (document.hidden || !missed) {
      return
    }
    missed = false
    window.clearInterval(timer)
    fn()
    timer = window.setInterval(tick, ms)
  }
  document.addEventListener('visibilitychange', shown)
  return () => {
    window.clearInterval(timer)
    document.removeEventListener('visibilitychange', shown)
  }
}
