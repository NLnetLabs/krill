<template>
    <div>
        <span v-if="hasTa">
            {{ $t("trustanchor.present") }}
        </span>
        <span v-else>
            {{ $t("trustanchor.absent") }}
            <el-form :inline="true">
                <el-form-item>
                    <el-button
                        class="retire"
                        icon="el-icon-plus"
                        type="primary"
                        round
                        size="mini"
                        @click="dialogFormVisible = true"
                    >{{ $t("trustanchor.add") }}</el-button>
                </el-form-item>
            </el-form>
        </span>

        <el-dialog :title="$t('trustanchor.add')"
                   :visible.sync="dialogFormVisible"
                   :close-on-click-modal="false">

            <el-form :model="form" :rules="rules" ref="add_ta_form">

                <el-form-item label="Base Rsync URI"
                              prop="base_rsync_uri"
                              placeholder="rsync://HOST/folder/">
                    <el-input v-model="form.base_rsync_uri" autocomplete="off"></el-input>
                </el-form-item>

                <el-form-item label="RRDP Notify URI"
                              prop="rrdp_notify_uri"
                              placeholder="https://HOST/notify.xml">
                    <el-input v-model="form.rrdp_notify_uri" autocomplete="off"></el-input>
                </el-form-item>

                <el-alert type="error" v-if="error" :closable="false">{{error}}</el-alert>
                <el-row type="flex" class="modal-footer" justify="end">
                    <el-form-item>
                        <el-button @click="reset_form('add_ta_form')">{{ $t('form.cancel')
                        }}</el-button>
                        <el-button
                                type="primary"
                                @click="submit_form('add_ta_form')"
                        >{{ $t('form.confirm') }}</el-button>
                    </el-form-item>
                </el-row>
            </el-form>

        </el-dialog>

    </div>

</template>

<script>
    // import router from "@/router";
    import APIService from "@/services/APIService.js";

    export default {

        data() {

            var check_rsync_uri = (rule, value, callback) => {
                if (value === "") {
                    callback(new Error(this.$t("form.required")));
                } else {
                    if (new RegExp(/rsync:\/\/[^\s]+\/[^\s]+\//gm).test(value)) {
                        callback();
                    } else {
                        callback(new Error(this.$t("form.rsync_uri_format")));
                    }
                }
            };

            var check_rrdp_notify_uri = (rule, value, callback) => {
                if (value === "") {
                    callback(new Error(this.$t("form.required")));
                } else {
                    if (new RegExp(/https:\/\/[^\s]+\//gm).test(value)) {
                        callback();
                    } else {
                        callback(new Error(this.$t("form.rrdp_uri_format")));
                    }
                }
            };

            return {
                hasTa: false,
                dialogFormVisible: false,
                taDetails: "",
                form: {
                    base_rsync_uri: "",
                    rrdp_notify_uri: ""
                },
                rules: {
                    base_rsync_uri: [{ validator: check_rsync_uri, required: true }],
                    rrdp_notify_uri: [{ validator: check_rrdp_notify_uri, required: true }]
                }
            };
        },
        created() {
            this.load_ta();
        },

        methods: {
            load_ta: function() {
                APIService.getTrustAnchor().then(response => {
                   if (response.statusCode == 200) {
                       this.hasTa = true;
                   }
                });
            },

            reset_form: function (form_name) {
                this.dialogFormVisible = false;
                this.$refs[form_name].resetFields()
            },

            submit_form: function (form_name) {
                this.$refs[form_name].validate(valid => {
                    if (valid) {
                        this.dialogFormVisible = false;
                        return true;
                    } else {
                        return false;
                    }
                });
            }
        }

    }

</script>