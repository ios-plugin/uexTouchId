//
//  EUExTouchID.m
//  EUExTouchID
//
//  Created by 黄锦 on 15/10/17.
//  Copyright © 2015年 AppCan. All rights reserved.
//

#import "EUExTouchID.h"
#import <LocalAuthentication/LocalAuthentication.h>
#import "EUtility.h"
#import "JSON.h"

@implementation EUExTouchID


-(void) verify :(NSMutableArray*)inArguments{
    NSString* hint=nil;
    if(inArguments.count >0){
        hint= [inArguments objectAtIndex:0];
    }
    
    LAContext* context = [[LAContext alloc] init];
    NSError* error = nil;
    
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
        //支持指纹验证
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:hint reply:^(BOOL success, NSError *error) {
            if (success) {
                [self cbVerify: YES code:[error localizedDescription]];
            }
            else
            {   //验证失败，或取消验证
                [self cbVerify: NO code:[error localizedDescription]];
            }
        }];
    }
    else
    {
        //不支持指纹识别,
        [self cbVerify: NO code:[error localizedDescription]];
    }
}

//callback
-(void) cbVerify:(BOOL)status code:(NSString*)reason{
    
    NSString *cbStr=[NSString stringWithFormat:@"if(uexTouchID.cbVerify != null){uexTouchID.cbVerify('%@','%@');}",@(status),reason];
    [EUtility brwView:meBrwView evaluateScript:cbStr];
}

@end
