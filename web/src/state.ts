import { reactive } from 'vue'

import { api, ApiError, type Me } from './api'
import { errorMessage } from './format'

// the administrator logged in, null when nobody is. error: why the session couldn't be checked, the server didn't
// answer say; '' when it answered
export const session = reactive<{ me: Me | null; checked: boolean; error: string }>({ me: null, checked: false, error: '' })

// checkSession asks the server who is logged in. Only its answer that nobody is logs out: when it can't answer, it's
// asked twice more, then the administrator of before stays, and error says why.
export async function checkSession(force = false): Promise<boolean> {
  if (!session.checked || force) {
    for (let attempt = 1; ; attempt++) {
      try {
        session.me = await api.me()
        session.error = ''
        break
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) {
          session.me = null
          session.error = ''
          break
        }
        if (attempt >= 3) {
          session.error = errorMessage(e)
          break
        }
        await new Promise((resolve) => setTimeout(resolve, 1000 * attempt))
      }
    }
    session.checked = true
  }
  return session.me !== null
}

// the role can do it: the server checks it anyway, the pages show only what works
export function isAdmin(): boolean {
  return session.me?.role === 'admin'
}

export function canManage(): boolean {
  return session.me?.role === 'admin' || session.me?.role === 'operator'
}

export interface Toast {
  id: number
  tone: 'success' | 'error'
  text: string
}

export const toasts = reactive<Toast[]>([])
let nextToast = 1

export function notify(text: string, tone: Toast['tone'] = 'success') {
  const id = nextToast++
  toasts.push({ id, tone, text })
  setTimeout(() => dismiss(id), tone === 'error' ? 8000 : 4000)
}

export function dismiss(id: number) {
  const index = toasts.findIndex((toast) => toast.id === id)
  if (index >= 0) {
    toasts.splice(index, 1)
  }
}

export interface Confirmation {
  title: string
  text: string
  action: string
  danger: boolean
  resolve: (ok: boolean) => void
}

export const confirmation = reactive<{ current: Confirmation | null }>({ current: null })

// confirm asks before an action that can't be undone
export function confirm(title: string, text: string, action: string, danger = true): Promise<boolean> {
  return new Promise((resolve) => {
    confirmation.current = { title, text, action, danger, resolve }
  })
}

export function answer(ok: boolean) {
  confirmation.current?.resolve(ok)
  confirmation.current = null
}

export async function download(name: string, text: string, type = 'text/plain') {
  const url = URL.createObjectURL(new Blob([text], { type }))
  const link = document.createElement('a')
  link.href = url
  link.download = name
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
