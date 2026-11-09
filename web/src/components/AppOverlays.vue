<script setup lang="ts">
import { answer, confirmation, dismiss, toasts } from '../state'
import AppIcon from './AppIcon.vue'
import UiButton from './UiButton.vue'
import UiModal from './UiModal.vue'
</script>

<template>
  <UiModal :open="confirmation.current !== null" :title="confirmation.current?.title ?? ''" @close="answer(false)">
    <p class="whitespace-pre-line">{{ confirmation.current?.text }}</p>
    <template #footer>
      <UiButton @click="answer(false)">Cancel</UiButton>
      <UiButton :variant="confirmation.current?.danger ? 'danger' : 'primary'" @click="answer(true)">
        {{ confirmation.current?.action }}
      </UiButton>
    </template>
  </UiModal>

  <div class="pointer-events-none fixed right-4 bottom-4 z-[60] flex w-full max-w-sm flex-col gap-2" aria-live="polite">
    <div
      v-for="toast in toasts"
      :key="toast.id"
      class="pointer-events-auto flex items-start gap-3 rounded-lg border bg-white p-3.5 text-sm shadow-lg dark:bg-slate-800"
      :class="toast.tone === 'error' ? 'border-rose-200 dark:border-rose-500/40' : 'border-slate-200 dark:border-slate-700'"
      :role="toast.tone === 'error' ? 'alert' : 'status'"
    >
      <AppIcon
        :name="toast.tone === 'error' ? 'alert' : 'check'"
        :class="toast.tone === 'error' ? 'text-rose-600' : 'text-emerald-600'"
      />
      <p class="flex-1">{{ toast.text }}</p>
      <button type="button" class="text-slate-400 hover:text-slate-700" aria-label="Dismiss" @click="dismiss(toast.id)">
        <AppIcon name="close" :size="16" />
      </button>
    </div>
  </div>
</template>
