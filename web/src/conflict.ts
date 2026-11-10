// Two administrators edit the same thing. A form opens with the version of what it edits; the server refuses to save
// it over a change made since (the error 'changed', with what it is now). The form then takes the changes of the
// other administrator on the fields this one didn't touch, keeps what this one typed, and says which fields both
// changed: nothing is lost without a word, and the next save, with the new version, is a choice.

import { ref } from 'vue'

import { ApiError } from './api'

export type Fields = Record<string, unknown>

export interface Conflict {
  // the administrator who saved meanwhile, '' when unknown, and when
  by: string
  at: number
  // the labels of the fields that took their changes, and of the ones both changed: those keep the typed values
  taken: string[]
  both: string[]
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b)

// merge compares field by field what the form opened with (base), what it has now (mine) and what was saved
// meanwhile (theirs)
export function merge<F extends Fields>(base: F, mine: F, theirs: F): { values: F; taken: (keyof F)[]; both: (keyof F)[] } {
  const values = { ...mine }
  const taken: (keyof F)[] = []
  const both: (keyof F)[] = []
  for (const key of Object.keys(theirs) as (keyof F)[]) {
    if (same(theirs[key], base[key])) {
      continue
    }
    if (same(mine[key], base[key])) {
      values[key] = theirs[key]
      taken.push(key)
    } else if (!same(mine[key], theirs[key])) {
      both.push(key)
    }
  }
  return { values, taken, both }
}

// useEditGuard keeps the version and the fields a form opened with. fieldsOf gives the fields of the form from what
// the server answers; labels name them, as the form does.
export function useEditGuard<V extends { version: number }, F extends Fields>(
  fieldsOf: (view: V) => F,
  labels: Record<keyof F, string>,
) {
  const version = ref(0)
  const conflict = ref<Conflict | null>(null)
  let base: F | null = null
  let theirs: F | null = null
  let both: (keyof F)[] = []

  // start: the form opens, to edit view, or to add one (null)
  function start(view: V | null) {
    version.value = view?.version ?? 0
    base = view ? structuredClone(fieldsOf(view)) : null
    theirs = null
    both = []
    conflict.value = null
  }

  // refused looks at the error of a save: null when it isn't a change made meanwhile. Else the values for the form,
  // and again when only what the form doesn't show changed: then it can be saved again at once.
  function refused(error: unknown, mine: F): { values: F; again: boolean } | null {
    if (!(error instanceof ApiError) || error.code !== 'changed' || !base) {
      return null
    }
    const current = error.data.current as V
    const now = fieldsOf(current)
    const result = merge(base, mine, now)
    base = structuredClone(now)
    theirs = now
    both = result.both
    version.value = current.version
    const again = result.taken.length === 0 && result.both.length === 0
    conflict.value = again
      ? null
      : {
          by: String(error.data.by ?? ''),
          at: Number(error.data.at ?? 0),
          taken: result.taken.map((key) => labels[key]),
          both: result.both.map((key) => labels[key]),
        }
    return { values: result.values, again }
  }

  // useTheirs gives the values saved by the other administrator for the fields both changed
  function useTheirs(): Partial<F> {
    const values: Partial<F> = {}
    if (theirs) {
      for (const key of both) {
        values[key] = structuredClone(theirs[key])
      }
    }
    both = []
    if (conflict.value) {
      conflict.value = { ...conflict.value, both: [] }
    }
    return values
  }

  return { version, conflict, start, refused, useTheirs }
}
