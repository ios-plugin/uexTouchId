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
    LAContext* ctx = [[LAContext alloc] init];
    NSError *error = nil;
    LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
    
    if (ACSystemVersion() >= 9.0 && mode.integerValue == 1) {
        policy = LAPolicyDeviceOwnerAuthentication;
    }
    if(![ctx canEvaluatePolicy:policy error:&error]){
        ACLogDebug(@"TouchID is unavailable: %@",error.localizedDescription);
        return @(error.code);
    }
    return @(kUexTouchIDNoError);
}

- (void)authenticate:(NSMutableArray *)inArguments{
    ACArgsUnpack(NSDictionary *info,ACJSFunctionRef *cb) = inArguments;

    NSString *hint = stringArg(info[@"hint"]);
    NSNumber *mode = numberArg(info[@"mode"]);
    
    __weak typeof (self) weakSelf = self;
    void (^callback)(NSInteger resultCode) = ^(NSInteger resultCode){
        [weakSelf jsCallbackExecuteByMainThread:cb withArguments:ACArgsPack(@(resultCode))];
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
- (void)jsCallbackExecuteByMainThread:(ACJSFunctionRef *)jsFunc withArguments:(NSArray *)args {
    if([NSThread isMainThread]){
        [jsFunc executeWithArguments:args];
    } else {
        dispatch_async(dispatch_get_main_queue(), ^{
            [jsFunc executeWithArguments:args];
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
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.webViewEngine callbackWithFunctionKeyPath:JSKeyPath arguments:arguments];
        });
    }
}

@end
