<script setup>
import { computed } from "vue";

const props = defineProps(["title", "logs"]);

const label = computed(() => {
  return props.logs.every(({ pass }) => pass) ? "✅" : "❌";
});

const count = computed(() => {
  return props.logs.length;
});
const countValid = computed(() => {
  return props.logs.filter(({ pass }) => pass).length;
});
</script>

<template>
  <li>
    <a class="uk-accordion-title" href>
      {{ label }} {{ title }} ({{ countValid }}/{{ count }})
    </a>
    <div class="uk-accordion-content">
      <p v-for="({ pass, message }, index) in logs" :key="index">
        <span v-if="pass" class="uk-label uk-label-success"> Success </span>
        <span v-else class="uk-label uk-label-danger"> Error </span>
        {{ message }}
      </p>
    </div>
  </li>
</template>
