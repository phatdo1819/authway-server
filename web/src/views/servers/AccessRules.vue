<script setup lang="ts">
import { computed, ref } from 'vue'

import { emptyRow, hasPorts, rowProblem, ruleProtocols, type AccessRow, type RuleProtocol } from '../../addresses'
import AppIcon from '../../components/AppIcon.vue'
import UiHelp from '../../components/UiHelp.vue'
import { fieldMessage } from '../../format'

// The access rules of a peer, a row each: the address, network or name, the traffic it allows, and its ports
const model = defineModel<AccessRow[]>({ required: true })
const props = defineProps<{ label: string; placeholder: string; addLabel: string; error?: string; helper?: string; help?: string }>()

// a row's problem shows once its field is left, not while it's typed
const editing = ref<AccessRow | null>(null)
function problem(row: AccessRow) {
  return editing.value === row ? '' : rowProblem(row)
}
const message = computed(() => {
  const problems = model.value.map(problem)
  if (problems.includes('ports')) {
    return fieldMessage('invalid_ports')
  }
  if (problems.includes('target')) {
    return 'Enter the address, network or name of each rule.'
  }
  return props.error ?? ''
})

function setProtocol(row: AccessRow, protocol: RuleProtocol) {
  row.protocol = protocol
  // all the traffic or ping: no ports
  if (!hasPorts(protocol)) {
    row.ports = ''
  }
}
function remove(index: number) {
  model.value = model.value.filter((_, i) => i !== index)
}
function rowLabel(row: AccessRow, index: number) {
  return row.target.trim() || `rule ${index + 1}`
}
const fieldClass =
  'block rounded-md border bg-white px-3 py-2 text-sm shadow-sm outline-none focus:ring-2 disabled:bg-slate-100 disabled:text-slate-500 dark:bg-slate-900 dark:disabled:bg-slate-800'
function borderOf(bad: boolean) {
  return bad
    ? 'border-rose-500 focus:ring-rose-500/30'
    : 'border-slate-300 focus:border-sky-600 focus:ring-sky-600/25 dark:border-slate-600'
}
</script>

<template>
  <fieldset>
    <legend class="mb-1.5 flex items-center gap-1.5 text-sm font-medium text-slate-800 dark:text-slate-200">
      {{ label }}
      <UiHelp v-if="help" :text="help" :label="label" />
    </legend>
    <span v-if="help" class="sr-only">{{ help }}</span>
    <div class="mb-1 hidden gap-2 pr-[2.625rem] text-xs font-medium text-slate-500 sm:flex dark:text-slate-400" aria-hidden="true">
      <span class="flex-1">Address, network or name</span>
      <span class="w-36">Traffic</span>
      <span class="w-28">Ports</span>
    </div>
    <div class="space-y-4 sm:space-y-2">
      <div v-for="(row, index) in model" :key="index" class="flex flex-wrap gap-2 sm:flex-nowrap">
        <input
          v-model="row.target"
          :placeholder="placeholder"
          :aria-label="`${label} ${index + 1}: address, network or name`"
          :aria-invalid="problem(row) === 'target'"
          class="w-full min-w-0 font-mono sm:w-auto sm:flex-1"
          :class="[fieldClass, borderOf(problem(row) === 'target')]"
          @focus="editing = row"
          @blur="editing = null"
        />
        <select
          :value="row.protocol"
          :aria-label="`${label} ${index + 1}: traffic`"
          class="min-w-0 flex-1 sm:w-36 sm:flex-none"
          :class="[fieldClass, borderOf(false)]"
          @change="setProtocol(row, ($event.target as HTMLSelectElement).value as RuleProtocol)"
        >
          <option v-for="option in ruleProtocols" :key="option.value" :value="option.value">{{ option.label }}</option>
        </select>
        <input
          v-model="row.ports"
          :disabled="!hasPorts(row.protocol)"
          :placeholder="hasPorts(row.protocol) ? 'All ports' : ''"
          :aria-label="`${label} ${index + 1}: ports`"
          :aria-invalid="problem(row) === 'ports'"
          class="w-28 min-w-0 font-mono"
          :class="[fieldClass, borderOf(problem(row) === 'ports')]"
          @focus="editing = row"
          @blur="editing = null"
        />
        <button
          type="button"
          class="rounded-md px-2 text-slate-500 hover:bg-slate-100 hover:text-rose-700 dark:hover:bg-slate-800"
          :aria-label="`Remove ${rowLabel(row, index)}`"
          @click="remove(index)"
        >
          <AppIcon name="trash" :size="18" />
        </button>
      </div>
    </div>
    <button
      type="button"
      class="mt-2 inline-flex items-center gap-1.5 text-sm font-medium text-sky-700 hover:text-sky-900 dark:text-sky-400 dark:hover:text-sky-300"
      @click="model = [...model, emptyRow()]"
    >
      <AppIcon name="plus" :size="16" />{{ addLabel }}
    </button>
    <p v-if="message" class="mt-1.5 text-sm text-rose-700 dark:text-rose-400">{{ message }}</p>
    <p v-else-if="helper" class="mt-1.5 text-sm text-slate-500 dark:text-slate-400">{{ helper }}</p>
  </fieldset>
</template>
