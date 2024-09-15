<script setup lang="ts">
import { computed } from "vue";
import * as Question from "../Question";

const props = defineProps<{
  index: number,
  question: Question.t
}>();

const type = computed(() => {
  if (Question.IsQuestionH(props.question)) {
    return "Homomorphic";
  } else if (Question.IsQuestionNH(props.question)) {
    return "NonHomomorphic";
  } else if (Question.IsQuestionL(props.question)) {
    return "Lists";
  } else {
    throw "Unknow question type";
  }
});
</script>

<template>
  <table class="uk-table uk-table-striped">
    <caption>
      Question {{index}}
    </caption>
    <tbody>
      <tr>
        <td>Type</td>
        <td><span class="uk-label">{{ type }}</span></td>
      </tr>
      <template v-if="type === 'Homomorphic'">
        <tr>
          <td>Question</td>
          <td>{{question.question}}</td>
        </tr>
        <tr>
          <td>Number of choices</td>
          <td>Between {{question.min}} and {{question.max}}</td>
        </tr>
        <tr>
          <td>Blank vote possible</td>
          <td>{{question.blank ? "Yes" : "No"}}</td>
        </tr>
        <tr v-for="(answer, index) in question.answers" v-bind:key="index">
          <td>Answer {{ index }}</td>
          <td>{{ answer }}</td>
        </tr>
        <tr v-if="question.extra">
          <td>Extra</td>
          <td>{{question.extra}}</td>
        </tr>
      </template>

      <template v-if="type === 'NonHomomorphic'">
        <tr>
          <td>Question</td>
          <td>{{question.value.question}}</td>
        </tr>
        <tr v-for="(answer, index) in question.value.answers" v-bind:key="index">
          <td>Answer {{ index }}</td>
          <td>{{ answer }}</td>
        </tr>
        <tr v-if="question.extra">
          <td>Extra</td>
          <td>{{question.extra}}</td>
        </tr>
      </template>

      <template v-if="type === 'Lists'">
        <tr>
          <td>Question</td>
          <td>{{question.value.question}}</td>
        </tr>
        <tr v-for="(answer, index) in question.value.answers" v-bind:key="index">
          <td>Answer {{ index }}</td>
          <td>{{ answer[0] + answer.slice(1).join(", ") }}</td>
        </tr>
        <tr v-if="question.extra">
          <td>Extra</td>
          <td>{{question.extra}}</td>
        </tr>
      </template>
    </tbody>
  </table>
</template>
