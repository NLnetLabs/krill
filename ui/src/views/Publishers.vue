<template>
  <div class="about">
    <h1>This is the publishers page</h1>
     <el-card class="box-card" v-for="publisher in publishers" :key="publisher.handle">
        <div class="text item">
          {{ publisher }}
        </div>
      </el-card>
  </div>
</template>

<script>
  import APIService from "@/services/APIService.js";
  export default {
    data() {
      return {
        publishers: {}
      }
    },
    created() {
      APIService.getPublishers()
      .then(response => {
        this.publishers = response.data;
      })
    }
  }
</script>

<style scoped>
.box-card {
  margin: 2rem;
}
</style>
