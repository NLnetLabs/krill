<template>
  <div>
    <h3 v-if="loading">
      <i class="el-icon-loading"></i>
      {{ $t("publishers.loading") }}
    </h3>

    <el-card class="box-card" v-if="!loading">
      <div slot="header" class="clearfix">
        <el-breadcrumb separator-class="el-icon-arrow-right">
          <el-breadcrumb-item :to="{ path: '/' }">{{ $t("publishers.publishers") }}</el-breadcrumb-item>
        </el-breadcrumb>
        <div class="search-input">
          <el-input
            size="mini"
            :placeholder="$t('publishers.search')"
            prefix-icon="el-icon-search"
            v-model="search"
            clearable
          ></el-input>
        </div>
      </div>
      <div class="text item">
        <ul>
          <li v-for="publisher in sortPublishers(filteredPublishers)" :key="publisher.handle">
            <router-link :to="{ name: 'publisherDetails', params: { handle: publisher.id }}">
              <el-button type="text">{{ publisher.id }}</el-button>
            </router-link>
          </li>
        </ul>
      </div>
    </el-card>
  </div>
</template>

<script>
import APIService from "@/services/APIService.js";
export default {
  data() {
    return {
      loading: false,
      publishers: [],
      search: ""
    };
  },
  computed: {
    filteredPublishers: function() {
      let src = this.search;
      return this.publishers.filter(function(publisher) {
        return publisher.id.toLowerCase().indexOf(src) > -1;
      });
    }
  },
  created() {
    this.loading = true;
    APIService.getPublishers().then(response => {
      this.loading = false;
      this.publishers = response.data.publishers;
    });
  },
  methods: {
    sortPublishers: function(publishers) {
      return [...publishers].sort(function(a, b) {
        const handleA = a.id.toLowerCase();
        const handleB = b.id.toLowerCase();

        if (handleA > handleB) {
          return 1;
        } else if (handleA < handleB) {
          return -1;
        }
        return 0;
      });
    }
  }
};
</script>

<style lang="scss" scoped>
.box-card {
  margin: 2rem;
}
.search-input {
  float: right;
  width: 200px;
  margin-top: -20px;
}
</style>
