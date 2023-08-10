//SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.4;

import { TransferHelper } from '@uniswap/lib/contracts/libraries/TransferHelper.sol';
import { IERC20 } from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import { Ownable } from '@openzeppelin/contracts/access/Ownable.sol';
import { EnumerableSet } from '@openzeppelin/contracts/utils/structs/EnumerableSet.sol';
import { ILBPFactory } from './interfaces/ILBPFactory.sol';
import { ILBP } from './interfaces/ILBP.sol';
import { IVault } from './interfaces/IVault.sol';
import { IJoeFactory } from './interfaces/IJoeFactory.sol';
import { IJoeRouter02 } from './interfaces/IJoeRouter02.sol';
import { IJoePair } from './interfaces/IJoePair.sol';

/**
 * @title SwerveLBP
 * @dev This contract manages {LBP} - Liquidity Bootstrapping Pool using {Balancer} as underlying layer
 */
contract SwerveLBP is Ownable {
    using EnumerableSet for EnumerableSet.AddressSet;

    struct PoolData {
        address owner;
        bool isFundTokenFirstInPair;
        uint256 fundTokenInputAmount;
    }

    struct SplitTokens {
        uint256 amountMainToPoolOwner;
        uint256 amountMainToTraderJoe;
        uint256 amountFundToPoolOwner;
        uint256 amountFundToTraderJoe;
        uint256 fee;
        uint256 fundTokenInputAmount;
    }

    struct ExitToTraderJoeData {
        bytes32 balancerPoolId;
        uint256 bptToBurn;
        uint256 fundDiff;
        uint256 mainDiff;
        address fundToken;
        address mainToken;
        address[] poolTokens;
    }

    struct PoolConfig {
        string name;
        string symbol;
        address[] tokens;
        uint256[] amounts;
        uint256[] weights;
        uint256[] endWeights;
        bool isFundTokenFirstInPair;
        uint256 swapFeePercentage;
        uint256 startTime;
        uint256 endTime;
    }

    enum ExitKind {
        EXACT_BPT_IN_FOR_ONE_TOKEN_OUT,
        EXACT_BPT_IN_FOR_TOKENS_OUT,
        BPT_IN_FOR_EXACT_TOKENS_OUT
    }

    mapping(address => PoolData) private _poolData;
    mapping(address => uint256) public feeRecipientsBPS; // fee recipient -> power
    EnumerableSet.AddressSet private _pools;
    EnumerableSet.AddressSet private _recipientAddresses;
    EnumerableSet.AddressSet private _allowedFundTokens;

    uint256 private constant _TEN_THOUSAND_BPS = 10_000;
    uint256 public immutable platformAccessFeeBPS;

    address public immutable lbpFactory;
    address public immutable vault;
    address public immutable traderJoeRouter;
    address public immutable traderJoeFactory;

    // Events
    event PoolCreated(
        address indexed pool,
        bytes32 poolId,
        string name,
        string symbol,
        address[] tokens,
        uint256[] weights,
        uint256 swapFeePercentage,
        address owner,
        bool swapEnabledOnStart
    );

    event PoolPaused(address indexed pool);
    event PoolUnpaused(address indexed pool);
    event SetNewSwapFeePercentage(address indexed pool, uint256 newFee);
    event JoinedPool(address indexed pool, address[] tokens, uint256[] amounts, bytes userData);

    event GradualWeightUpdateScheduled(
        address indexed pool,
        uint256 startTime,
        uint256 endTime,
        uint256[] endWeights
    );

    event SwapEnabledSet(address indexed pool, bool swapEnabled);

    event TransferredPoolOwnership(address indexed pool, address previousOwner, address newOwner);

    event TransferredToken(address indexed pool, address token, address to, uint256 amount);

    event TransferredFee(
        address indexed pool,
        address token,
        address feeRecipient,
        uint256 feeAmount
    );

    // Pool access control
    modifier onlyPoolOwner(address pool) {
        require(msg.sender == _poolData[pool].owner, '!owner');
        _;
    }

    modifier nonZeroAddress(address _target) {
        require(_target != address(0), 'Zero address');
        _;
    }

    /**
     * @dev Creates an instance of SwerveLBP and accepts address of LBP Factory from {Balancer}
     * @param _lbpFactory LBP Factory address
     * @param _platformAccessFeeBPS access fee in BPS. 1 - 0.1%, 10000 - 100%
     */
    constructor(
        address _lbpFactory,
        uint256 _platformAccessFeeBPS,
        address _traderJoeRouter,
        address _traderJoeFactory
    )
        nonZeroAddress(_lbpFactory)
        nonZeroAddress(_traderJoeRouter)
        nonZeroAddress(_traderJoeFactory)
    {
        require(_platformAccessFeeBPS <= 10000, 'Fee should not exceed 10000 BPs');
        platformAccessFeeBPS = _platformAccessFeeBPS;
        lbpFactory = _lbpFactory;
        vault = ILBPFactory(_lbpFactory).getVault();

        // set initial fee recipient to owner of contract
        _recipientAddresses.add(owner());
        feeRecipientsBPS[owner()] = _TEN_THOUSAND_BPS;

        traderJoeRouter = _traderJoeRouter;
        traderJoeFactory = _traderJoeFactory;

        _allowedFundTokens.add(
            0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E
        );
        _allowedFundTokens.add(
            0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7
        );
        _allowedFundTokens.add(0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7);
    }

    /**
     * Adds another fee recipient to the list of recipients by taking owner's power
     * @dev Power is a number in BP (from 0 to 10,000) that indicates how much the fee recipient will receive comparing
     *      to other fee recipients. Only contract owner can add a fee recipient, and, by doing so, the owner gives some
     *      of it's power to the new fee recipient. This is done to make sure that the sum of powers of all fee
     *      recipients adds up to a 10,000.
     * @param _recipient Recipient's address to be added
     * @param _power Recipient's power in BP
     */
    function addRecipientAddress(
        address _recipient,
        uint256 _power
    ) external onlyOwner nonZeroAddress(_recipient) {
        require(!isRecipientAddress(_recipient), 'Already a recipient');
        uint256 _ownerPower = feeRecipientsBPS[owner()];
        require(_ownerPower > _power, 'Owner does not have enough power');
        feeRecipientsBPS[owner()] -= _power;
        _recipientAddresses.add(_recipient);
        feeRecipientsBPS[_recipient] = _power;
    }

    /**
     * Removes a fee recipient address and moves it's power to the owner of this contract
     * @param _recipient Recipient's address to be removed
     */
    function removeRecipientAddress(address _recipient) external onlyOwner {
        require(_recipient != owner(), 'Recipient cannot be the owner');
        require(recipientAddressesCount() > 1, 'You cannot remove the last fee recipient');
        uint256 _power = feeRecipientsBPS[_recipient];
        if (_recipientAddresses.remove(_recipient)) {
            feeRecipientsBPS[owner()] += _power;
            feeRecipientsBPS[_recipient] = 0;
        } else {
            revert('Recipient was not removed');
        }
    }

    /**
     * Moves some power of a fee recipient to the owner of this contract
     * @param _recipientFrom Target recipient's address
     * @param _power Recipient's power in BP
     */
    function takePowerOfRecipientAddress(
        address _recipientFrom,
        uint256 _power
    ) external onlyOwner {
        require(feeRecipientsBPS[_recipientFrom] > _power, 'You cannot take all power');
        feeRecipientsBPS[_recipientFrom] -= _power;

        feeRecipientsBPS[owner()] += _power;
    }

    function updateWeightsGradually(
        address pool,
        uint256 startTime,
        uint256 endTime,
        uint256[] memory endWeights
    ) external nonZeroAddress(pool) onlyPoolOwner(pool) {
        ILBP(pool).updateWeightsGradually(startTime, endTime, endWeights);
        emit GradualWeightUpdateScheduled(pool, startTime, endTime, endWeights);
    }

    function setSwapFeePercentage(
        address pool,
        uint256 newSwapFeePercentage
    ) external nonZeroAddress(pool) onlyPoolOwner(pool) {
        ILBP(pool).setSwapFeePercentage(newSwapFeePercentage);
        emit SetNewSwapFeePercentage(pool, newSwapFeePercentage);
    }

    function pause(address pool) external nonZeroAddress(pool) onlyPoolOwner(pool) {
        ILBP(pool).setPaused(true);
        emit PoolPaused(pool);
    }

    function unpause(address pool) external nonZeroAddress(pool) onlyPoolOwner(pool) {
        ILBP(pool).setPaused(false);
        emit PoolUnpaused(pool);
    }

    /**
     * @dev Creates a pool and return the contract address of the new pool
     */
    function createLBP(PoolConfig memory poolConfig) external returns (address) {
        // 1: deposit tokens and approve vault
        require(poolConfig.tokens.length == 2, 'LBPs must have exactly two tokens');
        require(poolConfig.tokens[0] != poolConfig.tokens[1], 'LBP tokens must be unique');
        require(poolConfig.startTime > block.timestamp, 'LBP start time must be in the future');
        require(
            poolConfig.endTime > poolConfig.startTime,
            'LBP end time must be greater than start time'
        );
        require(poolConfig.tokens[0] < poolConfig.tokens[1], 'The order of tokens is incorrect');

        require(
            isAllowedFundToken(
                poolConfig.tokens[poolConfig.isFundTokenFirstInPair ? 0 : 1] /* fund token */
            ),
            'Fund token is not allowed'
        );

        // remember current token balance
        uint256 token0BalBefore = IERC20(poolConfig.tokens[0]).balanceOf(address(this));
        uint256 token1BalBefore = IERC20(poolConfig.tokens[1]).balanceOf(address(this));

        TransferHelper.safeTransferFrom(
            poolConfig.tokens[0],
            msg.sender,
            address(this),
            poolConfig.amounts[0]
        );
        TransferHelper.safeTransferFrom(
            poolConfig.tokens[1],
            msg.sender,
            address(this),
            poolConfig.amounts[1]
        );
        TransferHelper.safeApprove(poolConfig.tokens[0], vault, poolConfig.amounts[0]);
        TransferHelper.safeApprove(poolConfig.tokens[1], vault, poolConfig.amounts[1]);

        // 2: pool creation
        address pool = ILBPFactory(lbpFactory).create(
            poolConfig.name,
            poolConfig.symbol,
            poolConfig.tokens,
            poolConfig.weights,
            poolConfig.swapFeePercentage,
            address(this), // owner set to this proxy
            false // swaps disabled on start
        );

        bytes32 poolId = ILBP(pool).getPoolId();
        emit PoolCreated(
            pool,
            poolId,
            poolConfig.name,
            poolConfig.symbol,
            poolConfig.tokens,
            poolConfig.weights,
            poolConfig.swapFeePercentage,
            address(this),
            false
        );

        // 3: store pool data
        _poolData[pool] = PoolData(
            msg.sender,
            poolConfig.isFundTokenFirstInPair,
            poolConfig.amounts[poolConfig.isFundTokenFirstInPair ? 0 : 1]
        );
        assert(_pools.add(pool));

        bytes memory userData = abi.encode(0, poolConfig.amounts); // JOIN_KIND_INIT = 0

        // 4: deposit tokens into pool
        IVault(vault).joinPool(
            poolId,
            address(this), // sender
            address(this), // recipient
            IVault.JoinPoolRequest(poolConfig.tokens, poolConfig.amounts, userData, false)
        );
        emit JoinedPool(pool, poolConfig.tokens, poolConfig.amounts, userData);

        // 5: configure weights
        ILBP(pool).updateWeightsGradually(
            poolConfig.startTime,
            poolConfig.endTime,
            poolConfig.endWeights
        );
        emit GradualWeightUpdateScheduled(
            pool,
            poolConfig.startTime,
            poolConfig.endTime,
            poolConfig.endWeights
        );

        // 6: refund to user any excess of tokens 0 and 1
        uint256 token0BalAfter = IERC20(poolConfig.tokens[0]).balanceOf(address(this));
        uint256 token1BalAfter = IERC20(poolConfig.tokens[1]).balanceOf(address(this));

        if (token0BalAfter > token0BalBefore) {
            IERC20(poolConfig.tokens[0]).transfer(msg.sender, token0BalAfter - token0BalBefore);
        }
        if (token1BalAfter > token1BalBefore) {
            IERC20(poolConfig.tokens[1]).transfer(msg.sender, token1BalAfter - token1BalBefore);
        }

        return pool;
    }

    /**
     * @dev Enable or disables swaps.
     * Note: LBPs are created with trading disabled by default.
     */
    function setSwapEnabled(address pool, bool swapEnabled) external onlyPoolOwner(pool) {
        ILBP(pool).setSwapEnabled(swapEnabled);
        emit SwapEnabledSet(pool, swapEnabled);
    }

    /**
     * @dev Transfer ownership of the pool to a new owner
     */
    function transferPoolOwnership(
        address pool,
        address newOwner
    ) external nonZeroAddress(pool) onlyPoolOwner(pool) nonZeroAddress(newOwner) {
        address previousOwner = _poolData[pool].owner;
        _poolData[pool].owner = newOwner;
        emit TransferredPoolOwnership(pool, previousOwner, newOwner);
    }

    /**
     * @dev Exit a pool, burn the BPT token and transfer back the tokens.
     * - If maxBPTTokenOut is passed as 0, the function will use the total balance available for the BPT token.
     * - If maxBPTTokenOut is between 0 and the total of BPT available, that will be the amount used to burn.
     * maxBPTTokenOut must be greater than or equal to 0
     * - isStandardFee value should be true unless there is an issue with safeTransfer, in which case it can be passed
     * as false, and the fee will stay in the contract and later on distributed manualy to mitigate errors
     */
    function exitPool(
        address pool,
        uint256 maxBPTTokenOut,
        bool isStandardFee,
        uint256[] memory minAmountsOut
    ) external onlyPoolOwner(pool) {
        // 1. Get pool data
        bytes32 poolId = ILBP(pool).getPoolId();
        (address[] memory poolTokens, uint256[] memory balances, ) = IVault(vault).getPoolTokens(
            poolId
        );

        require(poolTokens.length == minAmountsOut.length, 'invalid input length');
        PoolData memory poolData = _poolData[pool];
        uint256 fundTokenIndex = poolData.isFundTokenFirstInPair ? 0 : 1;

        // 2. Specify the exact BPT amount to burn
        uint256 bptToBurn = _calcBPTokenToBurn(pool, maxBPTTokenOut);

        // 3. Exit pool and keep tokens in contract
        IVault(vault).exitPool(
            poolId,
            address(this),
            payable(address(this)),
            IVault.ExitPoolRequest(
                poolTokens,
                minAmountsOut,
                abi.encode(ExitKind.EXACT_BPT_IN_FOR_TOKENS_OUT, bptToBurn),
                false
            )
        );

        // 4. Get the amount of Fund token from the pool that was left behind after exit (dust)
        (, uint256[] memory balancesAfterExit, ) = IVault(vault).getPoolTokens(poolId);

        // 5. Distribute tokens and fees
        _distributeTokens(
            pool,
            poolTokens,
            balances[fundTokenIndex] - balancesAfterExit[fundTokenIndex],
            isStandardFee
        );
    }

    /**
     * Exits the Balancer pool and stakes a part of the tokens to Trader Joe pool
     *
     * @param pool Balancer pool that we're exiting
     * @param maxBPTTokenOut If maxBPTTokenOut is passed as 0, the function will use the total balance available for
     *                          the BPT token.
     *                       If maxBPTTokenOut is between 0 and the total of BPT available, that will be the amount used
     *                          to burn.
     * @param deadline Simply a deadline to add liquidity to Trader Joe
     * @param ratio A ratio of how much tokens shoud be returned to the pool owner vs how much should be staked to
     *              Trader Joe. The numeric value is from 0 (i.e. stake everything to Trader Joe) to 10000 (i.e. return
     *              everything to the pool owner)
     * @param isStandardFee Should be `true` unless there is an issue with safeTransfer, in which case it can be passed
     *                      as `false`, and the fee will stay in the contract and later on distributed manualy to
     *                      mitigate errors
     * @param minAmountsOutBalancer Array of minimum amounts of tokens that are expected from Balancer pool (to avoid
     *                              front running). Note that minAmountsOutBalancer = [token0MinAmount,
     *                              token1MinAmount], where token0.address < token1.address
     * @param minAmountsOutBalancer Array of minimum amounts of tokens that are expected to be staked to Trader Joe pool
     *                              (to avoid front running). Note that minAmountsOutBalancer = [token0MinAmount,
     *                              token1MinAmount], where token0.address < token1.address
     */
    function exitToTraderJoe(
        address pool,
        uint256 maxBPTTokenOut,
        uint256 deadline,
        uint16 ratio,
        bool isStandardFee,
        uint256[] memory minAmountsOutBalancer,
        uint256[] memory minAmountsInTraderJoe
    ) external onlyPoolOwner(pool) {
        ExitToTraderJoeData memory data; // this is to avoid "stack too deep" error

        // 1. Get pool data
        data.balancerPoolId = ILBP(pool).getPoolId();
        uint256[] memory balances;
        (data.poolTokens, balances, ) = IVault(vault).getPoolTokens(data.balancerPoolId);

        require(data.poolTokens.length == minAmountsOutBalancer.length, 'Invalid input length');
        require(data.poolTokens.length == minAmountsInTraderJoe.length, 'Invalid input length');
        PoolData memory poolData = _poolData[pool];

        // 2. Specify the exact BPT amount to burn
        data.bptToBurn = _calcBPTokenToBurn(pool, maxBPTTokenOut);
        // 3. Exit pool and keep tokens in contract
        IVault(vault).exitPool(
            data.balancerPoolId,
            address(this),
            payable(address(this)),
            IVault.ExitPoolRequest(
                data.poolTokens,
                minAmountsOutBalancer,
                abi.encode(ExitKind.EXACT_BPT_IN_FOR_TOKENS_OUT, data.bptToBurn),
                false
            )
        );

        // 4. Get the amount of Fund token from the pool that was left behind after exit (dust)
        (, uint256[] memory balancesAfterExit, ) = IVault(vault).getPoolTokens(data.balancerPoolId);

        SplitTokens memory split = _splitTokens(
            poolData.isFundTokenFirstInPair,
            balances,
            balancesAfterExit,
            poolData.fundTokenInputAmount,
            ratio
        );

        PoolData storage poolDataStorage = _poolData[pool];
        poolDataStorage.fundTokenInputAmount = split.fundTokenInputAmount;

        data.fundToken = data.poolTokens[poolData.isFundTokenFirstInPair ? 0 : 1];
        data.mainToken = data.poolTokens[poolData.isFundTokenFirstInPair ? 1 : 0];
        //  we are not pool creator we are Swerve contract and we are initiation addLiquidity
        IERC20(data.mainToken).approve(
            traderJoeRouter,
            split.amountMainToTraderJoe // amount1
        );
        IERC20(data.fundToken).approve(
            traderJoeRouter,
            split.amountFundToTraderJoe // amount0
        );

        // 5. Pull to TraderJoe
        if (ratio < _TEN_THOUSAND_BPS) {
            address joePair = IJoeFactory(traderJoeFactory).getPair(data.fundToken, data.mainToken);

            // Create TradeJoe pair if it doesn't exits
            if (joePair == address(0)) {
                joePair = IJoeFactory(traderJoeFactory).createPair(
                    data.poolTokens[0],
                    data.poolTokens[1]
                );
            }

            (uint256 reserve0Before, uint256 reserve1Before, ) = IJoePair(joePair).getReserves();
            assert(IJoePair(joePair).token0() == data.poolTokens[0]);
            assert(IJoePair(joePair).token1() == data.poolTokens[1]);

            // Note: these assignments is done to avoid "stack too deep" error
            uint256 _deadline = deadline;
            uint256 minAmount0 = minAmountsInTraderJoe[0];
            uint256 minAmount1 = minAmountsInTraderJoe[1];
            IJoeRouter02(traderJoeRouter).addLiquidity(
                data.fundToken,
                data.mainToken,
                split.amountFundToTraderJoe, // amount0
                split.amountMainToTraderJoe, // amount1
                minAmount0,
                minAmount1,
                msg.sender,
                _deadline
            );

            (uint256 reserve0After, uint256 reserve1After, ) = IJoePair(joePair).getReserves();

            // Refund any leftovers after Balancer withdrawal and TraderJoe deposit (accounting for fees)
            data.fundDiff = poolData.isFundTokenFirstInPair
                ? (reserve0After - reserve0Before)
                : (reserve1After - reserve1Before);
            data.mainDiff = poolData.isFundTokenFirstInPair
                ? (reserve1After - reserve1Before)
                : (reserve0After - reserve0Before);
            uint256 fundTokenLeftover = split.amountFundToTraderJoe - data.fundDiff;
            uint256 mainTokenLeftover = split.amountMainToTraderJoe - data.mainDiff;

            if (fundTokenLeftover > 0) {
                IERC20(data.fundToken).transfer(msg.sender, fundTokenLeftover);
            }
            if (mainTokenLeftover > 0) {
                IERC20(data.mainToken).transfer(msg.sender, mainTokenLeftover);
            }
        }

        // 6. Fees
        if (isStandardFee) {
            _distributePlatformAccessFee(pool, data.fundToken, split.fee);
        } else {
            _distributeSafeFee(pool, data.fundToken, split.fee);
        }

        // 7. Distribute tokens
        if (ratio > 0) {
            _transferTokenToMsgSender(pool, data.fundToken, split.amountFundToPoolOwner);
            _transferTokenToMsgSender(pool, data.mainToken, split.amountMainToPoolOwner);
        }
    }

    /**
     * @dev Checks if the pool address was created in this smart contract
     */
    function isPool(address pool) external view returns (bool) {
        return _pools.contains(pool);
    }

    /**
     * @dev Returns the total amount of pools created in the contract
     */
    function poolCount() external view returns (uint256) {
        return _pools.length();
    }

    /**
     * @dev Returns a pool for a specific index
     */
    function getPoolAt(uint256 index) external view returns (address) {
        return _pools.at(index);
    }

    /**
     * @dev Returns a fee recipient address for a specific index
     */
    function getRecipientAddressAt(uint256 index) external view returns (address) {
        return _recipientAddresses.at(index);
    }

    /**
     * @dev Returns an allowed fund token for a specific index
     * @param _index Index of the token
     */
    function getAllowedFundToken(uint256 _index) external view returns (address) {
        return _allowedFundTokens.at(_index);
    }

    /**
     * @dev Returns the pool's data saved during creation
     */
    function getPoolData(address pool) external view returns (PoolData memory poolData) {
        return _poolData[pool];
    }

    /**
     * @dev Adds a token to the allowed fund tokens list
     * @param _token Fund token to be added
     */
    function addAllowedFundToken(address _token) public onlyOwner nonZeroAddress(_token) {
        require(!isAllowedFundToken(_token), 'Already an allowed fund token');
        _allowedFundTokens.add(_token);
    }

    /**
     * @dev Removes a token from the allowed fund tokens list
     * @param _token Fund token to be removed
     */
    function removeAllowedFundToken(address _token) public onlyOwner {
        if (!_allowedFundTokens.remove(_token)) revert('Token was not removed');
    }

    /**
     * @dev Returns the total amount of allowed fund tokens
     */
    function allowedFundTokensCount() public view returns (uint256) {
        return _allowedFundTokens.length();
    }

    /**
     * @dev Checks if the address is a fee recipient
     */
    function isRecipientAddress(address _recipient) public view returns (bool) {
        return _recipientAddresses.contains(_recipient);
    }

    /**
     * @dev Returns the total amount of fee recipient addresses
     */
    function recipientAddressesCount() public view returns (uint256) {
        return _recipientAddresses.length();
    }

    /**
     * @dev Checks if the address is an allowed fund token
     * @param _token Fund token
     */
    function isAllowedFundToken(address _token) public view returns (bool) {
        return _allowedFundTokens.contains(_token);
    }

    /**
     * @dev Distributes the tokens to the owner and the fee to the fee recipients
     */
    function _distributeTokens(
        address pool,
        address[] memory poolTokens,
        uint256 fundTokenFromPool,
        bool isStandardFee
    ) internal {
        PoolData storage poolData = _poolData[pool];

        address mainToken = poolTokens[poolData.isFundTokenFirstInPair ? 1 : 0];
        address fundToken = poolTokens[poolData.isFundTokenFirstInPair ? 0 : 1];
        uint256 mainTokenBalance = IERC20(mainToken).balanceOf(address(this));
        uint256 remainingFundBalance = fundTokenFromPool;

        // if the amount of fund token increased during the LBP
        if (fundTokenFromPool > poolData.fundTokenInputAmount) {
            uint256 totalPlatformAccessFeeAmount = ((fundTokenFromPool -
                poolData.fundTokenInputAmount) * platformAccessFeeBPS) / _TEN_THOUSAND_BPS;
            // Fund amount after substracting the fee
            remainingFundBalance = fundTokenFromPool - totalPlatformAccessFeeAmount;
            if (isStandardFee) {
                _distributePlatformAccessFee(pool, fundToken, totalPlatformAccessFeeAmount);
            } else {
                _distributeSafeFee(pool, fundToken, totalPlatformAccessFeeAmount);
            }
        } else {
            poolData.fundTokenInputAmount -= fundTokenFromPool;
        }

        // Transfer the balance of the main token
        _transferTokenToMsgSender(pool, mainToken, mainTokenBalance);
        // Transfer the balanace of fund token excluding the platform access fee
        _transferTokenToMsgSender(pool, fundToken, remainingFundBalance);
    }

    /**
     * @dev calculate the amount of BPToken to burn.
     * - if maxBPTTokenOut is 0, everything will be burned
     * - else it will burn only the amount passed
     */
    function _calcBPTokenToBurn(
        address pool,
        uint256 maxBPTTokenOut
    ) internal view returns (uint256) {
        uint256 bptBalance = IERC20(pool).balanceOf(address(this));
        require(maxBPTTokenOut <= bptBalance, 'Specifed BPT out amount out exceeds owner balance');
        require(bptBalance > 0, 'Pool owner BPT balance is zero');
        return maxBPTTokenOut == 0 ? bptBalance : maxBPTTokenOut;
    }

    function _splitTokens(
        bool isFundTokenFirstInPair,
        uint256[] memory balances,
        uint256[] memory balancesAfterExit,
        uint256 fundTokenInputAmount,
        uint256 ratio
    ) internal view returns (SplitTokens memory) {
        require(ratio <= _TEN_THOUSAND_BPS, 'invalid ratio');
        uint256 fundTokenIndex = isFundTokenFirstInPair ? 0 : 1;
        uint256 mainTokenIndex = isFundTokenFirstInPair ? 1 : 0;
        uint256 totalPlatformAccessFeeAmount = 0;
        uint256 amountFund = balances[fundTokenIndex] - balancesAfterExit[fundTokenIndex];
        uint256 remainingFund = amountFund;

        if (amountFund > fundTokenInputAmount) {
            totalPlatformAccessFeeAmount =
                ((amountFund - fundTokenInputAmount) * platformAccessFeeBPS) /
                _TEN_THOUSAND_BPS;
            remainingFund = amountFund - totalPlatformAccessFeeAmount;
        } else {
            fundTokenInputAmount -= amountFund;
        }

        uint256 amountFundToPoolOwner = (remainingFund * ratio) / _TEN_THOUSAND_BPS;

        uint256 amountMain = balances[mainTokenIndex] - balancesAfterExit[mainTokenIndex];
        uint256 amountMainToPoolOwner = (amountMain * ratio) / _TEN_THOUSAND_BPS;

        return
            SplitTokens(
                amountMainToPoolOwner,
                amountMain - amountMainToPoolOwner,
                amountFundToPoolOwner,
                amountFund - totalPlatformAccessFeeAmount - amountFundToPoolOwner,
                totalPlatformAccessFeeAmount,
                fundTokenInputAmount
            );
    }

    /**
     * @dev Transfer token to pool owner
     */
    function _transferTokenToMsgSender(address pool, address token, uint256 amount) private {
        TransferHelper.safeTransfer(token, msg.sender, amount);
        emit TransferredToken(pool, token, msg.sender, amount);
    }

    /**
     * @dev Send fee to owner of contract.
     *      Only used for exits where there was a transfer error between fee recipients
     */
    function _distributeSafeFee(address pool, address fundToken, uint256 totalFeeAmount) private {
        TransferHelper.safeTransfer(fundToken, owner(), totalFeeAmount);
        emit TransferredFee(pool, fundToken, owner(), totalFeeAmount);
    }

    /**
     * @dev Distribute fee between recipients
     */
    function _distributePlatformAccessFee(
        address pool,
        address fundToken,
        uint256 totalFeeAmount
    ) private {
        uint256 recipientsLength = _recipientAddresses.length();
        for (uint256 i = 0; i < recipientsLength; i++) {
            address recipientAddress = _recipientAddresses.at(i);
            // calculate amount for each recipient based on the their feeRecipientsBPS
            uint256 proportionalAmount = (totalFeeAmount * feeRecipientsBPS[recipientAddress]) /
                _TEN_THOUSAND_BPS;
            TransferHelper.safeTransfer(fundToken, recipientAddress, proportionalAmount);
            emit TransferredFee(pool, fundToken, recipientAddress, proportionalAmount);
        }
    }
}