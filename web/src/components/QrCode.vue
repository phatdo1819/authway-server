<script setup lang="ts">
import QRCode from 'qrcode'
import { ref, watchEffect } from 'vue'

// a QR code drawn here, in the browser: its content never leaves the page
const props = defineProps<{ text: string; label: string }>()
const source = ref('')

watchEffect(async () => {
  source.value = await QRCode.toDataURL(props.text, { margin: 1, width: 280, errorCorrectionLevel: 'M' })
})
</script>

<template>
  <img v-if="source" :src="source" :alt="label" width="280" height="280" class="mx-auto rounded-lg bg-white p-2" />
</template>
