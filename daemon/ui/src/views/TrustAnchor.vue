<template>
  <div>
    <el-card class="box-card">
      <div slot="header" class="clearfix">
        <el-breadcrumb separator-class="el-icon-arrow-right">
          <el-breadcrumb-item :to="{ path: '/' }">{{ $t("trustanchor.ta") }}</el-breadcrumb-item>
        </el-breadcrumb>
      </div>
      <div class="text item">
        <div v-if="hasTa">
          <div class="message">{{ $t("trustanchor.present") }}</div>
          <el-table :data="[taData]" style="width: 100%">
            <el-table-column prop="resources.asn.Blocks" label="ASNs"></el-table-column>
            <el-table-column prop="resources.v4" label="IPv4"></el-table-column>
            <el-table-column prop="resources.v6" label="IPv6"></el-table-column>
            <el-table-column prop="repo_info.base_uri" label="Base URI"></el-table-column>
            <el-table-column prop="repo_info.rpki_notify" label="RPKI notify"></el-table-column>
          </el-table>

          <el-form :inline="true" class="download-anchor">
            <el-form-item>
              <a href="/ta/ta.tal">{{ $t("trustanchor.downloadTal")}}</a>
            </el-form-item>
            <el-form-item>
              <el-button
                icon="el-icon-upload"
                type="primary"
                round
                size="mini"
                @click="publishTrustAnchor()"
              >{{ $t("trustanchor.publish") }}</el-button>
            </el-form-item>
          </el-form>
        </div>
        <div v-else>
          <div class="message">{{ $t("trustanchor.absent") }}</div>
          <el-form :inline="true">
            <el-form-item>
              <el-button
                icon="el-icon-plus"
                type="primary"
                round
                size="mini"
                @click="dialogFormVisible = true"
              >{{ $t("trustanchor.add") }}</el-button>
            </el-form-item>
          </el-form>
        </div>
      </div>
    </el-card>

    <el-dialog
      :title="$t('trustanchor.add')"
      :visible.sync="dialogFormVisible"
      :close-on-click-modal="false"
    >
      {{ $t("trustanchor.sure") }}
      <div style="height: 20px"></div>

      <el-form :inline="true">
        <el-row type="flex" class="modal-footer" justify="end">
          <el-form-item>
            <el-button @click="hideInitForm()">
              {{ $t('form.cancel')
              }}
            </el-button>
            <el-button type="primary" @click="initTrustAnchor()">{{ $t('form.confirm') }}</el-button>
          </el-form-item>
        </el-row>
      </el-form>
    </el-dialog>
  </div>
</template>

<script>
import APIService from "@/services/APIService.js";

export default {
  data() {
    return {
      hasTa: null,
      dialogFormVisible: false,
      taData: {}
    };
  },
  created() {
    this.loadTa();
  },
  methods: {
    loadTa: function() {
      const self = this;
      APIService.getTrustAnchor()
        .then(response => {
          self.hasTa = true;
          self.taData = response.data;
          response.toString();
        })
        .catch(() => {
          self.hasTa = false;
        });
    },

    hideInitForm: function() {
      this.dialogFormVisible = false;
    },

    initTrustAnchor: function() {
      APIService.initTrustAnchor();
      this.loadTa();
      this.dialogFormVisible = false;
    },

    publishTrustAnchor: function() {
      APIService.publishTrustAnchor();
    }
  }
};
</script>

<style lang="scss" scoped>
a {
  color: #f63107;
  font-size: 14px;
  text-decoration: none;
  &:hover {
    color: #f85a39;
  }
}
.box-card {
  margin: 2rem;
}
.message {
  font-size: 14px;
  margin-top: 1rem;
  margin-bottom: 1rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid #f9eadd;
}
.download-anchor {
  margin-top: 2rem;
}
</style>
