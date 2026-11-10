<script setup lang="ts">
import { computed } from 'vue'

import type { Conflict } from '../conflict'
import { ago, dateTime } from '../format'
import { session } from '../state'
import UiButton from './UiButton.vue'
import UiNotice from './UiNotice.vue'

// what another administrator saved while this form was open: see conflict.ts
const props = defineProps<{ conflict: Conflict | null; noun: string }>()
const emit = defineEmits<{ theirs: [] }>()

const who = computed(() => {
  const by = props.conflict?.by ?? ''
  if (!by) {
    return 'Another administrator'
  }
  return by === session.me?.username ? 'You, in another window,' : by
})

function list(labels: string[]): string {
  return labels.length > 1 ? labels.slice(0, -1).join(', ') + ' and ' + labels[labels.length - 1] : labels[0]
}
</script>

<template>
  <UiNotice v-if="conflict" tone="warning" :title="`${who} saved this ${noun} while you had it open`">
    <div class="space-y-2">
      <p :title="dateTime(conflict.at)">Saved {{ ago(conflict.at) }}. Nothing of yours is saved yet.</p>
      <p v-if="conflict.taken.length">
        Their changes are in the form now: <strong>{{ list(conflict.taken) }}</strong>. What you changed stays.
      </p>
      <template v-if="conflict.both.length">
        <p>
          You both changed <strong>{{ list(conflict.both) }}</strong>: the form keeps yours, and saving replaces theirs.
        </p>
        <UiButton size="sm" @click="emit('theirs')">Use theirs instead</UiButton>
      </template>
      <p>Check the form, then save again.</p>
    </div>
  </UiNotice>
</template>
