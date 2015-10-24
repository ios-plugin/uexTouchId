//
//  EUExTouchId.m
//  EUExTouchId
//
//  Created by xrg on 15/9/19.
//  Copyright (c) 2015年 ray_MGL. All rights reserved.
//

#import "EUExTouchId.h"
#import "JSON.h"
#import <LocalAuthentication/LocalAuthentication.h>




@implementation EUExTouchId

#pragma mark - super

- (id)initWithBrwView:(EBrowserView *)eInBrwView {
    
    if (self = [super initWithBrwView:eInBrwView]) {
        
    }
    
    return self;
    
}

#pragma mark - public

- (void)check:(NSMutableArray *)array {
    
    if ([[[UIDevice currentDevice] systemVersion] floatValue] < 8.0) {
        
        [self jsSuccessWithName:@"uexTouchId.cbCheck" opId:1 dataType:UEX_CALLBACK_DATATYPE_INT intData:1];
        
    }
    
    NSError * error = nil;
    
    LAContext * context = [LAContext new];
    
    BOOL ret = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
    
    if (ret) {
        
        [self jsSuccessWithName:@"uexTouchId.cbCheck" opId:0 dataType:UEX_CALLBACK_DATATYPE_INT intData:0];
        
    } else {
        
        [self jsSuccessWithName:@"uexTouchId.cbCheck" opId:1 dataType:UEX_CALLBACK_DATATYPE_TEXT intData:(int)error.code];
        
    }
    
}

- (void)verify:(NSMutableArray *)array {
    
    if ([[[UIDevice currentDevice] systemVersion] floatValue] < 8.0) {
        
        [self jsSuccessWithName:@"uexTouchId.cbVerify" opId:1 dataType:UEX_CALLBACK_DATATYPE_INT intData:1];
        
    }
    
    NSString * jsonStr = [array count] > 0 ? [array objectAtIndex:0] : @"";
    
    NSDictionary * jsonDict = [jsonStr JSONValue];
    
    NSString * localizedReason = [jsonDict objectForKey:@"reason"] ? [jsonDict objectForKey:@"reaon"] : @"Use Touch ID To Login.";
    
    NSString * localizedFallbackTitle = [jsonDict objectForKey:@"fallBackTitle"] ? [jsonDict objectForKey:@"fallBackTitle"] : @"";

    NSError * error = nil;
    
    LAContext * context = [LAContext new];
    
    context.localizedFallbackTitle = localizedFallbackTitle;
    
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
        
        __weak typeof(self) weakSelf = self;
        
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:localizedReason reply:^(BOOL success, NSError *error) {
            
            if (success) {
                
                NSDictionary * dict = [NSDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithInt:0],@"opId",[NSNumber numberWithInteger:0],@"data", nil];
                
                [weakSelf performSelectorOnMainThread:@selector(callBack:) withObject:dict waitUntilDone:NO];
                
                
            } else {
                
                NSDictionary * dict = [NSDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithInt:1],@"opId",[NSNumber numberWithInteger: error.code],@"data", nil];
                
                [weakSelf performSelectorOnMainThread:@selector(callBack:) withObject:dict waitUntilDone:NO];
                
            }
            
        }];
        
    } else {
        
        [self jsSuccessWithName:@"uexTouchId.cbVerify" opId:1 dataType:UEX_CALLBACK_DATATYPE_INT intData:1];
        
    }
    
}

#pragma mark - privite

- (void)callBack:(id)userInfo {
    
    NSDictionary * dict = (NSDictionary *)userInfo;
    
    [self jsSuccessWithName:@"uexTouchId.cbVerify" opId:[[dict objectForKey:@"opId"] intValue] dataType:UEX_CALLBACK_DATATYPE_INT strData:[dict objectForKey:@"data"]];
    
}

@end
