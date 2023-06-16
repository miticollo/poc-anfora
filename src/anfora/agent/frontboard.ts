/*
 * These hooks are the frida version of the AppSync hooks.
 * Credit goes to akemin-dayo for the original hooks.
 *
 * See also: https://github.com/akemin-dayo/AppSync/blob/master/AppSyncUnified-FrontBoard/AppSyncUnified-FrontBoard.x
 */

const {
    FBSSignatureValidationService,
    FBApplicationTrustData,
} = ObjC.classes;

if (FBSSignatureValidationService !== undefined) {
    // Located in iOS 14.x and above's FrontBoardServices.framework
    Interceptor.attach(FBSSignatureValidationService['- trustStateForApplication:'].implementation, {
        onEnter(args): void {
            this.application = new ObjC.Object(args[2]);
        },
        onLeave(retval): void {
            console.log(`Original response for FBSSignatureValidationService trustStateForApplication: application == ${this.application}, retval == ${retval}`);
            // Returns 8 for a trusted, valid app.
            // Returns 4 when showing the 「"アプリ"はもう利用できません」 message.
            retval.replace(ptr(0x8));
        },
    });
} else if (FBApplicationTrustData !== undefined) {
    // Located in iOS 9.3.x 〜 iOS 13.x's FrontBoard.framework
    Interceptor.attach(FBApplicationTrustData['- trustStateWithTrustRequiredReasons:'].implementation, {
        onEnter(args): void {
            this.reasons = args[2];
        },
        onLeave(retval): void {
            console.log(`Original response for FBApplicationTrustData trustStateWithTrustRequiredReasons: reasons == ${this.reasons}, retval == ${retval}`);
            // Returns 2 for a trusted, valid app.
            retval.replace(ptr(2));
        }
    });

    Interceptor.attach(FBApplicationTrustData['- trustState'].implementation, {
        onLeave(retval): void {
            console.log(`Original response for FBApplicationTrustData trustState: retval == ${retval}`);
            retval.replace(ptr(2));
        }
    });
}
