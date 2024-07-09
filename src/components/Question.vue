<script setup>
import { computed } from "vue";

const props = defineProps(["question"]);

const type = computed(() => {
  return props.question.type === undefined
    ? "Homomorphic"
    : props.question.type;
});

const supported = computed(() => {
  return props.question.type === undefined || props.question.type === "Lists";
});

console.log(props.question);
</script>

<template>
  <li>
    <a class="uk-accordion-title" href>
      Question: "{{ question.question }}"
      <span class="uk-label">{{ type }}</span>
      <span v-if="supported" class="uk-label uk-label-success">Supported</span>
      <span v-else class="uk-label uk-label-danger">Unsupported</span>
    </a>

    <div class="uk-accordion-content">
      <h4 v-for="(answer, index) in question.answers" v-bind:key="index">
        Answer {{ index }} : {{ answer }}
      </h4>
      <div class="uk-margin">
        <p>
          Selection between {{ question.min }} and {{ question.max }} choices
        </p>
        <p>
          {{ question.blank ? "Blank vote allowed" : "Blank vote not allowed" }}
        </p>
      </div>
    </div>
  </li>
</template>
