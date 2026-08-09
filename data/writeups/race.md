# RACE — technique corpus

## transfer_amount
- target: Bank
- payload hint: parallel transfer
- bounty: $15000.0 (2024)
- source: aggregated:hacktivity race transfer 2024
- summary: Transfer race double-credit

## balance_double_spend
- target: Fintech
- payload hint: Parallel withdraw requests
- bounty: $12000.0 (2024)
- source: https://hackerone.com/reports/333333
- summary: Withdraw race condition doubles balance

## multi_coupon_chain
- target: E-commerce
- payload hint: parallel coupons same order
- bounty: $8500.0 (2024)
- source: aggregated:hacktivity race coupon 2024
- summary: Coupon stacking race

## gift_card_fulfill
- target: E-commerce
- payload hint: parallel claims
- bounty: $8000.0 (2024)
- source: aggregated:hacktivity race giftcard 2024
- summary: GC claim race

## loyalty_points
- target: E-commerce
- payload hint: parallel points add
- bounty: $7000.0 (2024)
- source: aggregated:hacktivity race points 2024
- summary: Points accrual race

## subscription_upgrade_downgrade
- target: SaaS
- payload hint: parallel cancel/reactivate
- bounty: $7000.0 (2024)
- source: aggregated:hacktivity race sub 2024
- summary: Subscription state race

## access_delegate
- target: Cloud
- payload hint: parallel ACL swap
- bounty: $6500.0 (2024)
- source: aggregated:hacktivity race acl 2024
- summary: ACL swap race

## password_reset_tok
- target: Web
- payload hint: parallel reset using same token
- bounty: $6000.0 (2024)
- source: aggregated:hacktivity race reset 2024
- summary: Reset token race

## sms_otp_rate
- target: Web
- payload hint: parallel OTP submit saturate
- bounty: $6000.0 (2024)
- source: aggregated:hacktivity race otp 2024
- summary: OTP brute race

## 2fa_reuse
- target: Web
- payload hint: parallel 2FA submit
- bounty: $5500.0 (2024)
- source: aggregated:hacktivity race 2fa 2024
- summary: 2FA code reuse race

## file_download_private
- target: Web
- payload hint: resolve-then-check race (TOCTOU)
- bounty: $5500.0 (2024)
- source: aggregated:hacktivity toctou 2024
- summary: Download TOCTOU

## coupon_reuse
- target: E-commerce
- payload hint: 50 parallel coupon redemptions
- bounty: $5000.0 (2025)
- source: https://hackerone.com/reports/323232
- summary: Coupon redemption race enables unlimited reuse

## admin_approval_race
- target: Web
- payload hint: parallel approve
- bounty: $5000.0 (2024)
- source: aggregated:hacktivity race approval 2024
- summary: Approval state race

## out_of_stock_race
- target: E-commerce
- payload hint: parallel stock decrements
- bounty: $4500.0 (2024)
- source: aggregated:hacktivity race stock 2024
- summary: Stock oversell race

## email_verify_race
- target: Web App
- payload hint: Parallel email verification
- bounty: $4000.0 (2025)
- source: https://hackerone.com/reports/343434
- summary: Email verification token reusable via race

## file_upload_idempotency
- target: Web
- payload hint: parallel upload then delete
- bounty: $4000.0 (2024)
- source: aggregated:hacktivity race upload 2024
- summary: Upload validate/move race

## invite_token_regen
- target: Web
- payload hint: parallel invite
- bounty: $3500.0 (2024)
- source: aggregated:hacktivity race invite 2024
- summary: Invite token reuse

## session_fixation_race
- target: Web
- payload hint: parallel session swap
- bounty: $3500.0 (2024)
- source: aggregated:hacktivity race session 2024
- summary: Session fix race

## register_email
- target: Web
- payload hint: parallel email confirm
- bounty: $3000.0 (2024)
- source: aggregated:hacktivity race email 2024
- summary: Email confirm race

## api_webhook_delivery
- target: SaaS
- payload hint: parallel webhook retry
- bounty: $3000.0 (2024)
- source: aggregated:hacktivity race webhook 2024
- summary: Webhook dedupe race

## feature_flag_flip
- target: SaaS
- payload hint: parallel flag toggles
- bounty: $2000.0 (2024)
- source: aggregated:hacktivity race ff 2024
- summary: Feature flag race minor

## kys_like_race
- target: Web
- payload hint: unlike/like parallel state
- bounty: $1500.0 (2024)
- source: aggregated:hacktivity race like 2024
- summary: Like race minor
