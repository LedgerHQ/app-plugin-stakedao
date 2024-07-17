#include <stdbool.h>
#include "stakedao_plugin.h"

bool copy_amount_with_ticker(const uint8_t *amount,
                             uint8_t amount_size,
                             uint8_t amount_decimals,
                             char *ticker,
                             uint8_t ticker_size,
                             char *out_buffer,
                             uint8_t out_buffer_size) {
    char tmp_buffer[100] = {0};
    if (!amountToString(amount, amount_size, amount_decimals, "", tmp_buffer, 100)) {
        return false;
    }
    uint8_t amount_len = strnlen(tmp_buffer, sizeof(tmp_buffer));
    memcpy(out_buffer, tmp_buffer, amount_len);
    memcpy(out_buffer + amount_len, " ", 1);
    memcpy(out_buffer + amount_len + 1, ticker, ticker_size);
    out_buffer[out_buffer_size - 1] = '\0';
    return true;
}

static void copy_amount(uint8_t *dst, size_t dst_len, uint8_t *src) {
    size_t len = MIN(dst_len, PARAMETER_LENGTH);
    memcpy(dst, src, len);
}

static bool set_strategy_name(ethQueryContractUI_t *msg, stakedao_parameters_t *context) {
    strlcpy(msg->title, "Strategy", msg->titleLength);
    strlcpy(msg->msg, context->strategy, msg->msgLength);
    return true;
}

static bool set_rewards_name(ethQueryContractUI_t *msg) {
    strlcpy(msg->title, "Rewards", msg->titleLength);
    strlcpy(msg->msg, "Claim", msg->msgLength);
    return true;
}

static bool set_nft_boost_name(ethQueryContractUI_t *msg) {
    strlcpy(msg->title, "Strategy", msg->titleLength);
    strlcpy(msg->msg, "NFTBoost", msg->msgLength);
    return true;
}

static bool set_rewards_receive_name(ethQueryContractUI_t *msg) {
    strlcpy(msg->title, "Receive", msg->titleLength);
    strlcpy(msg->msg, "xSDT", msg->msgLength);
    return true;
}

static bool set_angle_rewards_receive_name(ethQueryContractUI_t *msg) {
    strlcpy(msg->title, "Receive", msg->titleLength);
    strlcpy(msg->msg, "ANGLE", msg->msgLength);
    return true;
}

static bool set_curve_pool_name(ethQueryContractUI_t *msg, stakedao_parameters_t *context) {
    strlcpy(msg->title, "Pool", msg->titleLength);
    strlcpy(msg->msg, context->vault, msg->msgLength);
    return true;
}

static bool set_masterchef_name(ethQueryContractUI_t *msg, stakedao_parameters_t *context) {
    strlcpy(msg->title, "LP Farming PID", msg->titleLength);

    uint8_t *pid_number = context->pid;
    uint8_t pid_number_size = sizeof(context->pid);
    return amountToString(pid_number, pid_number_size, 0, "", msg->msg, msg->msgLength);
}

static bool set_want_name(ethQueryContractUI_t *msg, stakedao_parameters_t *context) {
    strlcpy(msg->title, "Want", msg->titleLength);
    strlcpy(msg->msg, context->want, msg->msgLength);
    return true;
}

static bool set_masterchef_want_name(ethQueryContractUI_t *msg) {
    strlcpy(msg->title, "Want", msg->titleLength);
    strlcpy(msg->msg, "LP", msg->msgLength);
    return true;
}

static bool set_want_name_sd_token(ethQueryContractUI_t *msg, stakedao_parameters_t *context) {
    strlcpy(msg->title, "Want", msg->titleLength);
    strlcpy(msg->msg, context->vault, msg->msgLength);
    return true;
}

static bool set_nft_want_name(ethQueryContractUI_t *msg) {
    strlcpy(msg->title, "Want", msg->titleLength);
    strlcpy(msg->msg, "StakeDAO NFTs", msg->msgLength);
    return true;
}

static bool set_curve_pool_amount(ethQueryContractUI_t *msg) {
    strlcpy(msg->title, "Amount", msg->titleLength);
    strlcpy(msg->msg, "Selected", msg->msgLength);
    return true;
}

static bool set_amount_with_all(ethQueryContractUI_t *msg) {
    strlcpy(msg->title, "Amount", msg->titleLength);
    strlcpy(msg->msg, "ALL", msg->msgLength);
    return true;
}

static bool set_nft_id(ethQueryContractUI_t *msg, stakedao_parameters_t *context) {
    strlcpy(msg->title, "Id", msg->titleLength);
    uint8_t *pid_number = context->pid;
    uint8_t pid_number_size = sizeof(context->pid);
    return amountToString(pid_number, pid_number_size, 0, "", msg->msg, msg->msgLength);
}

static bool set_nft_amount(ethQueryContractUI_t *msg) {
    strlcpy(msg->title, "Amount", msg->titleLength);
    strlcpy(msg->msg, "1", msg->msgLength);
    return true;
}

static bool set_eth_amount(ethQueryContractUI_t *msg) {
    strlcpy(msg->title, "Amount", msg->titleLength);

    // The number of ETH associated with this transaction is
    // located in `msg->pluginSharedRO->txContent->value.
    uint8_t *eth_amount = msg->pluginSharedRO->txContent->value.value;
    uint8_t eth_amount_size = msg->pluginSharedRO->txContent->value.length;

    // `amountToString` is a utility function that converts a `uin256_t` to
    //  a string.
    // `18` and `ETH ` refer to the decimals and the ticker.
    return amountToString(eth_amount, eth_amount_size, 18, "ETH", msg->msg, msg->msgLength);
}

static bool set_reward_amount(ethQueryContractUI_t *msg, stakedao_parameters_t *context) {
    strlcpy(msg->title, "Amount", msg->titleLength);
    return amountToString(context->amount,
                          sizeof(context->amount),
                          18,
                          "xSDT",
                          msg->msg,
                          msg->msgLength);
}

static bool set_amount(ethQueryContractUI_t *msg, stakedao_parameters_t *context) {
    strlcpy(msg->title, "Amount", msg->titleLength);
    return copy_amount_with_ticker(context->amount,
                                   sizeof(context->amount),
                                   context->decimals,
                                   context->want,
                                   sizeof(context->want),
                                   msg->msg,
                                   msg->msgLength);
}

static bool set_sd_amount(ethQueryContractUI_t *msg, stakedao_parameters_t *context) {
    strlcpy(msg->title, "Amount", msg->titleLength);
    return copy_amount_with_ticker(context->amount,
                                   sizeof(context->amount),
                                   context->decimals,
                                   context->vault,
                                   sizeof(context->vault),
                                   msg->msg,
                                   msg->msgLength);
}

static bool set_strategy_ui(ethQueryContractUI_t *msg, stakedao_parameters_t *context) {
    strlcpy(msg->title, "Strategy", msg->titleLength);

    msg->msg[0] = '0';
    msg->msg[1] = 'x';
    uint64_t chainid = 0;
    return getEthAddressStringFromBinary(context->address, msg->msg + 2, chainid);
}

bool handle_query_contract_ui_vaults(ethQueryContractUI_t *msg, stakedao_parameters_t *context) {
    bool ret = false;

    // Copy the vault address prior to any process
    ethPluginSharedRO_t *pluginSharedRO = (ethPluginSharedRO_t *) msg->pluginSharedRO;
    copy_amount(context->address, sizeof(context->address), pluginSharedRO->txContent->destination);

    // find information about vault
    uint8_t i;
    stakedaoStrategy_t *currentVault = NULL;
    for (i = 0; i < NUM_STAKEDAO_STRATEGIES; i++) {
        currentVault = (stakedaoStrategy_t *) PIC(&STAKEDAO_STRATEGIES[i]);
        if (memcmp(currentVault->address, context->address, ADDRESS_LENGTH) == 0) {
            context->decimals = currentVault->decimals;
            memcpy(context->want, currentVault->want, MAX_STRATEGY_TICKER_LEN);
            memcpy(context->strategy, currentVault->strategy, MAX_STRATEGY_TICKER_LEN);
            memcpy(context->vault, currentVault->vault, MAX_STRATEGY_TICKER_LEN);
            break;
        }
    }
    uint8_t j;
    stakedaoCrvPool_t *currentPool = NULL;
    for (j = 0; j < NUM_CURVE_POOLS; j++) {
        currentPool = (stakedaoCrvPool_t *) PIC(&CURVE_POOLS[j]);
        if (memcmp(currentPool->address, context->address, ADDRESS_LENGTH) == 0) {
            memcpy(context->want, currentPool->want, MAX_STRATEGY_TICKER_LEN);
            memcpy(context->vault, currentPool->pool, MAX_STRATEGY_TICKER_LEN);
            break;
        }
    }
    switch (msg->screenIndex) {
        case 0:
            switch (context->selectorIndex) {
                case LP_DEPOSIT:
                case LP_WITHDRAW:
                    ret = set_masterchef_name(msg, context);
                    break;
                case REWARDS_CLAIM:
                case ANGLE_GET_REWARD:
                    ret = set_rewards_name(msg);
                    break;
                case NFT_STAKE:
                case NFT_UNSTAKE:
                    ret = set_nft_boost_name(msg);
                    break;
                case CURVE_ADD_L_2:
                case CURVE_ADD_L_3:
                case CURVE_ADD_L_3_UNDER:
                    ret = set_curve_pool_name(msg, context);
                    break;
                default:
                    ret = set_strategy_name(msg, context);
                    break;
            }
            break;
        case 1:
            switch (context->selectorIndex) {
                case LP_DEPOSIT:
                case LP_WITHDRAW:
                    ret = set_masterchef_want_name(msg);
                    break;
                case OPT_WITHDRAW_ETH:
                case OPT_WITHDRAW_UNDERLYING:
                case OPT_WITHDRAW_CRVLP:
                case VAULT_WITHDRAW:
                case SANCTUARY_LEAVE:
                    ret = set_want_name_sd_token(msg, context);
                    break;
                case REWARDS_CLAIM:
                    ret = set_rewards_receive_name(msg);
                    break;
                case NFT_STAKE:
                    ret = set_nft_want_name(msg);
                    break;
                case NFT_UNSTAKE:
                    ret = set_nft_want_name(msg);
                    break;
                case ANGLE_GET_REWARD:
                    ret = set_angle_rewards_receive_name(msg);
                    break;
                default:
                    ret = set_want_name(msg, context);
                    break;
            }
            break;
        case 2:
            switch (context->selectorIndex) {
                case VAULT_DEPOSIT_ALL:
                case PREMIUM_EXIT:
                case PREMIUM_GETREWARD:
                case ANGLE_GET_REWARD:
                    ret = set_amount_with_all(msg);
                    break;
                case OPT_DEPOSIT_ETH:
                    ret = set_eth_amount(msg);
                    break;
                case OPT_WITHDRAW_ETH:
                case OPT_WITHDRAW_UNDERLYING:
                case OPT_WITHDRAW_CRVLP:
                case VAULT_WITHDRAW:
                case SANCTUARY_LEAVE:
                    ret = set_sd_amount(msg, context);
                    break;
                case VAULT_DEPOSIT:
                case SANCTUARY_ENTER:
                case OPT_DEPOSIT_UNDERLYING:
                case OPT_DEPOSIT_CRVLP:
                case PALACE_STAKE:
                case PALACE_WITHDRAW:
                case PREMIUM_STAKE:
                case PREMIUM_WITHDRAW:
                case LP_DEPOSIT:
                case LP_WITHDRAW:
                    ret = set_amount(msg, context);
                    break;
                case REWARDS_CLAIM:
                    ret = set_reward_amount(msg, context);
                    break;
                case NFT_STAKE:
                    ret = set_nft_id(msg, context);
                    break;
                case NFT_UNSTAKE:
                    ret = set_nft_amount(msg);
                    break;
                case CURVE_ADD_L_2:
                case CURVE_ADD_L_3:
                case CURVE_ADD_L_3_UNDER:
                    ret = set_curve_pool_amount(msg);
                    break;
                default:
                    break;
            }
            break;
        case 3:
            ret = set_strategy_ui(msg, context);
            break;
        // Keep this
        default:
            PRINTF("Received an invalid screenIndex\n");
    }
    return ret;
}

void handle_query_contract_ui(ethQueryContractUI_t *msg) {
    stakedao_parameters_t *context = (stakedao_parameters_t *) msg->pluginContext;
    bool ret = false;

    memset(msg->title, 0, msg->titleLength);
    memset(msg->msg, 0, msg->msgLength);

    switch (context->selectorIndex) {
        default:
            ret = handle_query_contract_ui_vaults(msg, context);
            break;
    }
    msg->result = ret ? ETH_PLUGIN_RESULT_OK : ETH_PLUGIN_RESULT_ERROR;
}
