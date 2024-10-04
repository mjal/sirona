<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{
  credentials: string[];
}>();
</script>

<template>
  <table class="uk-table uk-table-striped">
    <caption>
      Credentials
    </caption>
    <tbody>
      <tr v-for="(credential, index) in credentials" v-bind:key="index">
        <td>{{ credential }}</td>
      </tr>
    </tbody>
  </table>
</template>
