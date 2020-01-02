//
//  EUExTouchID.m
//  EUExTouchID
//
//  Created by 黄锦 on 15/10/17.
//  Copyright © 2015年 AppCan. All rights reserved.
//

#import "EUExTouchID.h"
#import <LocalAuthentication/LocalAuthentication.h>







static const NSInteger kUexTouchIDNoError = 0;
static const NSInteger kUexTouchIDNotAvailable = -6; // -6 = LAErrorTouchIDNotAvailable


@implementation EUExTouchID


- (NSNumber *)canAuthenticate:(NSMutableArray *)inArguments{
    ACArgsUnpack(NSDictionary *info) = inArguments;
    NSNumber *mode = numberArg(info[@"mode"]);
    if (!NSClassFromString(@"LAContext")) {
        //8.0以下的系统
        return @(kUexTouchIDNotAvailable);
    }
    LAContext *context = [LAContext new];
    NSError *error = nil;
    LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
    if (ACSystemVersion() >= 9.0 && mode.integerValue == 1) {
        policy = LAPolicyDeviceOwnerAuthentication;
    }
    BOOL supportEvaluatePolicy = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
    
    //    LAPolicyDeviceOwnerAuthenticationWithBiometrics iOS8.0以上支持，只有指纹验证功能
    //    LAPolicyDeviceOwnerAuthentication iOS 9.0以上支持，包含指纹验证与输入密码的验证方式
    if (@available(iOS 11.0, *)) {
        if (context.biometryType == LABiometryTypeTouchID) {
            // 指纹
            if (error) {
                // 支持指纹但没有设置
                return @(error.code);
            } else {
                return @(kUexTouchIDNoError);
            }
        }else{
            //非touchid类型即为不支持
            return @(kUexTouchIDNotAvailable);
        }
    } else {
        //11以下系统走原逻辑
        if(!supportEvaluatePolicy){
            ACLogDebug(@"TouchID is unavailable: %@",error.localizedDescription);
            return @(error.code);
        }else{
            return @(kUexTouchIDNoError);
        }
    }
    return @(kUexTouchIDNotAvailable);
}

- (void)authenticate:(NSMutableArray *)inArguments{
    ACArgsUnpack(NSDictionary *info, __block ACJSFunctionRef *cb) = inArguments;

    NSString *hint = stringArg(info[@"hint"]);
    NSNumber *mode = numberArg(info[@"mode"]);
    
//    __weak typeof (self) weakSelf = self;
//    typeof(ACJSFunctionRef **) inCb = &cb;
    void (^callback)(NSInteger resultCode) = ^(NSInteger resultCode){
//        [weakSelf jsCallbackExecuteByMainThread:inCb withArguments:ACArgsPack(@(resultCode))];
        if([NSThread isMainThread]){
            [cb executeWithArguments:ACArgsPack(@(resultCode))];
            cb = nil;
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                [cb executeWithArguments:ACArgsPack(@(resultCode))];
                cb = nil;
            });
        }
    };
    
    if (!NSClassFromString(@"LAContext")){
        callback(kUexTouchIDNotAvailable);
        return;
    }
    
    LAContext* ctx = [[LAContext alloc] init];
    NSError* error = nil;
    LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
    if (ACSystemVersion() >= 9.0 && mode.integerValue == 1) {
        policy = LAPolicyDeviceOwnerAuthentication;
    }
    if (![ctx canEvaluatePolicy:policy error:&error]) {
        //不支持指纹识别
        callback(error.code);
        return;
    }
    [ctx evaluatePolicy:policy localizedReason:hint reply:^(BOOL success, NSError * _Nullable error) {
        NSLog(@"uexTouchID===>reply: %d, isMainThread? %d", success, [NSThread isMainThread]);
        if (success) {
            //验证成功
            callback(kUexTouchIDNoError);
        }else{
            //验证失败，或取消验证
            callback(error.code);
        }
    }];
}




-(void) verify :(NSMutableArray*)inArguments{
    ACArgsUnpack(NSString *hint) = inArguments;
    LAContext* context = [[LAContext alloc] init];
    __weak typeof (self) weakSelf = self;
    void (^callback)(BOOL result,NSString *reason) = ^(BOOL result,NSString *reason){
        [weakSelf callbackWithFunctionKeyPathByMainThread:@"uexTouchID.cbVerify" arguments:ACArgsPack(@(result),reason)];
    };
    

    NSError* error = nil;
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:hint reply:^(BOOL success, NSError *error) {
            if (success) {
                //验证成功
                callback(YES,nil);
            }else{
                //验证失败，或取消验证
                callback(NO,error.localizedDescription);
            }
        }];
    }else{
        //不支持TouchID
        callback(NO,error.localizedDescription);
    }
}


#pragma mark - Callback Common

/**
 保证在主线程中完成JS回调操作
 
 @param jsFunc 回调JS方法
 @param args 参数
 */
- (void)jsCallbackExecuteByMainThread:(ACJSFunctionRef **)jsFunc withArguments:(NSArray *)args {
    if([NSThread isMainThread]){
        [*jsFunc executeWithArguments:args];
        *jsFunc = nil;
    } else {
        dispatch_async(dispatch_get_main_queue(), ^{
            [*jsFunc executeWithArguments:args];
            *jsFunc = nil;
        });
    }
}

/**
 保证在主线程中完成JS回调操作
 
 @param jsString 回调需要执行的JS字符串
 */
- (void)callbackWithFunctionKeyPathByMainThread:(NSString *)JSKeyPath arguments:(nullable NSArray *)arguments {
    if([NSThread isMainThread]){
        [self.webViewEngine callbackWithFunctionKeyPath:JSKeyPath arguments:arguments];
    } else {
        __weak typeof (self) weakSelf = self;
        dispatch_async(dispatch_get_main_queue(), ^{
            [weakSelf.webViewEngine callbackWithFunctionKeyPath:JSKeyPath arguments:arguments];
        });
    }
}

@end
