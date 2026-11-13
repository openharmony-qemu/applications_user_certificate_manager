/*
 * Copyright (c) 2026 Harmony Contrib
 * SPDX-License-Identifier: Apache-2.0
 */
import Want from '@ohos.app.ability.Want';
import UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';
import certificateDialog from '@ohos.security.certManagerDialog';
import certManagerModel, { CMModelErrorCode, CMModelOptType, CmDialogOperationType,
  DialogErrorCode } from '../model/CertMangerModel';
import { CertInfoVo } from '../model/CertManagerVo/CertInfoVo';
import checkUserAuthModel from '../model/CheckUserAuthModel';
import { ResourceUtils } from '../common/util/ResourceUtils';
import Logger from '../common/util/Logger';

const logger: Logger = new Logger('CertificateUninstallPage');
// cm_type.h / cm_dialog_api_common.h map this actual operation failure to
// the public 29700003. The existing permission, syscap and CA policy gates
// remain in the native launcher and certificate service.
const REMOVE_FAILED: number = -5;
const storage: LocalStorage = LocalStorage.getShared();

@Entry(storage)
@Component
struct CertificateUninstallPage {
  @State private subject: string = '';
  @State private issuer: string = '';
  @State private fingerprint: string = '';
  @State private callerName: string = '';
  @State private loaded: boolean = false;
  @State private pending: boolean = false;
  private active: boolean = false;
  private authFinished: boolean = false;
  private uri: string = '';
  private original: Uint8Array = new Uint8Array();
  private session: UIExtensionContentSession = storage.get<UIExtensionContentSession>('session') as UIExtensionContentSession;
  private want: Want = storage.get<Want>('want') as Want;

  aboutToAppear(): void {
    this.active = true;
    const params: Record<string, Object> | undefined = this.want?.parameters;
    if ((this.want?.deviceId !== undefined && this.want.deviceId.length > 0) ||
      params?.['pageType'] !== 5 || params?.['operationType'] !== CmDialogOperationType.UNINSTALL ||
      params?.['certType'] !== certificateDialog.CertificateType.CA_CERT ||
      typeof params?.['certUri'] !== 'string' || typeof params?.['bundleName'] !== 'string') {
      this.finish(DialogErrorCode.DIALOG_ERROR_PARAM_INVALID);
      return;
    }
    this.uri = params['certUri'] as string;
    this.callerName = params['bundleName'] as string;
    if (this.uri.length === 0 || this.uri.length > 256 || this.uri.includes('\u0000')) {
      this.finish(DialogErrorCode.DIALOG_ERROR_PARAM_INVALID);
      return;
    }
    certManagerModel.getCertOrCred(CMModelOptType.CM_MODEL_OPT_USER_CA, this.uri,
      (code: CMModelErrorCode, cert: CertInfoVo | undefined) => {
        if (!this.active) { return; }
        if (code !== CMModelErrorCode.CM_MODEL_ERROR_SUCCESS || cert === undefined ||
          cert.uri !== this.uri || cert.cert.length === 0) {
          this.finish(REMOVE_FAILED);
          return;
        }
        this.original = new Uint8Array(cert.cert);
        this.subject = cert.subjectName;
        this.issuer = cert.issuerName;
        this.fingerprint = cert.fingerprintSha256;
        this.loaded = true;
      });
  }

  aboutToDisappear(): void { this.active = false; }

  private finish(code: number): void {
    if (!this.active) { return; }
    this.active = false;
    this.session.terminateSelfWithResult({ resultCode: code });
  }

  private sameCertificate(actual: CertInfoVo | undefined): boolean {
    if (actual === undefined || actual.uri !== this.uri || actual.cert.length !== this.original.length) {
      return false;
    }
    for (let index: number = 0; index < this.original.length; ++index) {
      if (actual.cert[index] !== this.original[index]) { return false; }
    }
    return true;
  }

  private confirm(): void {
    if (!this.active || !this.loaded || this.pending) { return; }
    this.pending = true;
    const title: string = ResourceUtils.getResourceString(getContext(this), $r('app.string.Identity_Authentication'));
    checkUserAuthModel.auth(title, (authenticated: boolean) => {
      if (!this.active || this.authFinished) { return; }
      this.authFinished = true;
      if (!authenticated) {
        this.finish(DialogErrorCode.DIALOG_OPERATION_CANCELS);
        return;
      }
      // Re-read the exact displayed certificate after user authentication;
      // neither a stale session nor a changed URI may authorize deletion.
      certManagerModel.getCertOrCred(CMModelOptType.CM_MODEL_OPT_USER_CA, this.uri,
        (code: CMModelErrorCode, actual: CertInfoVo | undefined) => {
          if (!this.active) { return; }
          if (code !== CMModelErrorCode.CM_MODEL_ERROR_SUCCESS || !this.sameCertificate(actual)) {
            this.finish(REMOVE_FAILED);
            return;
          }
          certManagerModel.deleteCertOrCred(CMModelOptType.CM_MODEL_OPT_USER_CA, this.uri,
            (removed: CMModelErrorCode) => {
              if (!this.active) { return; }
              if (removed !== CMModelErrorCode.CM_MODEL_ERROR_SUCCESS) {
                this.finish(REMOVE_FAILED);
                return;
              }
              logger.info(`CA uninstall committed uri:${this.uri}`);
              // The original native void callback closes this modal and
              // resolves exactly once only after the real service succeeded.
              this.active = false;
              this.session.sendData({ uri: this.uri });
            });
        });
    });
  }

  build() {
    Column({ space: 16 }) {
      Text($r('app.string.ca_uninstall_title')).fontSize(24).id('cert-uninstall-title')
      Text(this.callerName).id('cert-uninstall-requester')
      Text($r('app.string.ca_uninstall_warning'))
      Scroll() {
        Column({ space: 12 }) {
          Text(this.subject).id('cert-uninstall-subject')
          Text(this.issuer).id('cert-uninstall-issuer')
          Text(this.fingerprint).id('cert-uninstall-fingerprint')
        }
      }.layoutWeight(1)
      Row({ space: 16 }) {
        Button($r('app.string.deleteAllCredCancel')).id('cert-uninstall-cancel')
          .enabled(!this.pending)
          .onClick(() => this.finish(DialogErrorCode.DIALOG_OPERATION_CANCELS))
        Button($r('app.string.deleteAllCredDelete')).id('cert-uninstall-confirm')
          .enabled(this.loaded && !this.pending)
          .onClick(() => this.confirm())
      }
    }.padding(24).width('100%').height('100%')
      .backgroundColor($r('sys.color.background_secondary'))
  }
}
