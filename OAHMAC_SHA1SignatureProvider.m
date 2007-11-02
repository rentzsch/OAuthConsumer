//
//  OAHMAC_SHA1SignatureProvider.m
//  OAuthConsumer
//
//  Created by Jon Crosby on 10/19/07.
//  Copyright 2007 Kaboomerang LLC. All rights reserved.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.


#import "OAHMAC_SHA1SignatureProvider.h"


@implementation OAHMAC_SHA1SignatureProvider

- (NSString *)name {
    return @"HMAC-SHA1";
}

- (NSString *)signClearText:(NSString *)text withSecret:(NSString *)secret {
    NSData *secretData = [secret dataUsingEncoding:NSUTF8StringEncoding];
    NSData *clearTextData = [text dataUsingEncoding:NSUTF8StringEncoding];

    //HMAC-SHA1
    HMAC_CTX hmacContext;
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int resultLength;
    
    HMAC_CTX_init(&hmacContext);
    HMAC_Init(&hmacContext, [secretData bytes], [secretData length], EVP_sha1());
    HMAC_Update(&hmacContext, [clearTextData bytes], [clearTextData length]);
    HMAC_Final(&hmacContext, result, &resultLength);
    
    //Base64 Encoding
    char *base64Result;
    
    BIO *bio = BIO_new(BIO_s_mem());
    BIO *b64Filter = BIO_new(BIO_f_base64());
    bio = BIO_push(b64Filter, bio);
    BIO_write(bio, result, resultLength);
    BIO_flush(bio);
    
    long base64ResultLength = BIO_get_mem_data(bio, &base64Result);
    base64Result[base64ResultLength-1] = '\0'; // -1 is used to remove the "courtesy" newline added by this library
    
    NSString *base64EncodedResult = [NSString stringWithCString:base64Result encoding:NSUTF8StringEncoding];
    
    BIO_free_all(bio);
    HMAC_CTX_cleanup(&hmacContext);
    
    return base64EncodedResult;
}

@end
