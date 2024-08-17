<script setup>
import { computed } from "vue";

const props = defineProps(["state"]);
const questions = props.state.setup.election.questions;
const result = props.state.result.payload.result;

const questions_h = questions.filter((question) => question.type === undefined);
</script>

<template>
  <div class="uk-card uk-card-default uk-card-body uk-margin">
    <h3 class="uk-card-title uk-h3 uk-text-center">Results</h3>
    <ul>
      <table
        class="uk-table uk-table-divider"
        v-for="(question, i) in questions_h"
        v-bind:key="i"
      >
        <h4 class="uk-h4">{{ question.question }}</h4>
        <tbody>
          <tr v-for="(answer, j) in question.answers" v-bind:key="j">
            <td>{{ answer }}</td>
            <td>{{ result[i][j] }}</td>
          </tr>
        </tbody>
      </table>
    </ul>
  </div>
</template>
