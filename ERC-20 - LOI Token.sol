// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract GATE is ReentrancyGuard {
    using SafeMath for uint256;

    string public name = "GATE";
    string public symbol = "GATE";
    uint8 public decimals = 18;
    uint256 public totalSupply = 50e9 * 1e18; // Total supply of 50 billion
    uint256 private constant maxSupply = 100e9 * 1e18; // Maximum supply of 100 billion

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    mapping(bytes32 => bool) public _auditTrail;
    mapping(address => uint256) private _lastDepositTime;


    uint256 private maxTxAmount = 250e6 * 1e18;

    address private _owner;
    bool private _paused;
    bool private _emergencyStop;
    bool private _releaseStopped;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Paused(address account);
    event Unpaused(address account);
    event AuditTrail(bytes32 indexed auditHash);
    event EmergencyStop();
    event Release();

    modifier onlyOwner() {
        require(msg.sender == _owner, "Caller is not the owner");
        _;
    }

    modifier whenNotPaused() {
        require(!_paused || msg.sender == _owner, "Contract is paused");
        _;
    }

    modifier whenNotPausedAndNotOwner() {
        require(!_paused || msg.sender != _owner, "Contract is paused");
        _;
    }

    modifier whenNotStopped() {
        require(!_emergencyStop, "Contract is stopped");
        _;
    }

    modifier whenStopped() {
        require(_emergencyStop, "Contract is not stopped");
        _;
    }

    modifier whenReleaseStopped() {
        require(!_releaseStopped, "Release is already stopped");
        _;
    }

   constructor() {
    _owner = msg.sender;
    
    // Allocate 11.5 billion tokens for the token sale
    uint256 tokensForSale = 11.5e9 * 1e18;
    _balances[address(this)] = tokensForSale;
    emit Transfer(address(0), address(this), tokensForSale);

    // Allocate the remaining tokens to the owner
    uint256 tokensForOwner = totalSupply.sub(tokensForSale);
    _balances[msg.sender] = tokensForOwner;
    emit Transfer(address(0), msg.sender, tokensForOwner);
}

    function pause() external onlyOwner nonReentrant {
        require(!_paused, "Contract is already paused");
        _paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner nonReentrant {
        require(_paused, "Contract is not paused");
        _paused = false;
        emit Unpaused(msg.sender);
    }

    function emergencyStop() external onlyOwner whenNotStopped nonReentrant {
        require(!_emergencyStop, "Contract is already stopped");
        _emergencyStop = true;
        emit EmergencyStop();
    }

    function release() external onlyOwner whenNotPaused whenNotStopped nonReentrant {
        require(!_emergencyStop, "Contract is stopped");
        require(!_releaseStopped, "Release is already stopped");

        _releaseStopped = true;
        emit Release();
    }

    function resume() external onlyOwner whenNotPaused whenStopped whenReleaseStopped nonReentrant {
        require(!_emergencyStop, "Contract is in an emergency stop"); // additional check
        _emergencyStop = false;
        _releaseStopped = false;
        emit Release();
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

   function deposit(uint256 amount) external returns (bool) {
        require(amount > 0, "Deposit amount must be greater than zero");

        _transferInternal(msg.sender, address(this), amount);

        bytes32 auditHash = keccak256(abi.encodePacked("deposit", msg.sender, amount, block.timestamp));
        _auditTrail[auditHash] = true;
        emit AuditTrail(auditHash);

        // Update the last deposit timestamp for the sender (optional if you don't need it)
        _lastDepositTime[msg.sender] = block.timestamp;

        return true;
    }

    function withdraw(uint256 amount) external whenNotStopped returns (bool) {
        require(amount > 0, "Withdrawal amount must be greater than zero");
        require(!_emergencyStop, "Contract is stopped");
        require(_balances[msg.sender] >= amount, "Insufficient balance");

        _transferInternal(address(this), msg.sender, amount);

        bytes32 auditHash = keccak256(abi.encodePacked("withdraw", msg.sender, amount, block.timestamp));
        _auditTrail[auditHash] = true;
        emit AuditTrail(auditHash);

        return true;
    }

    function withdrawByOwner(uint256 amount) external onlyOwner whenNotPausedAndNotOwner returns (bool) {
        require(amount > 0, "Withdraw amount must be greater than zero");

        require(amount <= _balances[msg.sender], "Insufficient balance");
        require(totalSupply.add(amount) <= maxSupply, "Total supply exceeds maximum supply");

        _transferInternal(address(this), msg.sender, amount);

        bytes32 auditHash = keccak256(abi.encodePacked("withdraw", msg.sender, amount, block.timestamp));
        _auditTrail[auditHash] = true;
        emit AuditTrail(auditHash);

        return true;
    }

    function isContract(address account) internal view returns (bool) {
    if (account == address(this)) {
        return false; // Exclude the token contract itself from the check
    }

    uint256 codeSize;
    assembly {
        codeSize := extcodesize(account)
    }
    return codeSize > 0;
}

    function transfer(address recipient, uint256 amount) external whenNotPaused returns (bool) {
    require(recipient != address(0), "Transfer to zero address");
    require(amount > 0, "Transfer amount must be greater than zero");
    require(amount <= _balances[msg.sender], "Insufficient balance");
    require(amount <= maxTxAmount, "Transfer amount exceeds the maxTxAmount");

    uint256 taxAmount = amount.mul(2).div(100);

    _transferInternal(msg.sender, address(this), amount.sub(taxAmount));

    _transferInternal(msg.sender, _owner, taxAmount);

    _transferInternal(address(this), recipient, amount.sub(taxAmount));

    bytes32 auditHash = keccak256(abi.encodePacked("transfer", msg.sender, recipient, amount, block.timestamp));
    _auditTrail[auditHash] = true;
    emit AuditTrail(auditHash);

    return true;
}

    function _transferInternal(address sender, address recipient, uint256 amount) internal whenNotPausedAndNotOwner whenNotStopped {
        require(sender != address(0), "Transfer from the zero address");
        require(recipient != address(0), "Transfer to the zero address");
        require(amount > 0, "Transfer amount must be greater than zero");

        if (sender == address(this)) {
            totalSupply = totalSupply.sub(amount);
        } else if (recipient == address(this)) {
            totalSupply = totalSupply.add(amount);
        }

        require(totalSupply <= maxSupply, "Maximum supply exceeded");
        require(_balances[sender] >= amount, "Insufficient balance");

        _balances[sender] -= amount;
        _balances[recipient] += amount;

        emit Transfer(sender, recipient, amount);
    }

    function _approve(address owner, address spender, uint256 amount) internal nonReentrant {
        require(owner != address(0), "approve from the zero address");
        require(spender != address(0), "approve to the zero address");
        require(amount <= _balances[owner], "Insufficient balance to approve allowance");

        uint256 currentAllowance = _allowances[owner][spender];
        require(amount > currentAllowance, "Allowance is already greater than or equal to the requested amount");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function transferFrom(address sender, address recipient, uint256 amount) external whenNotPaused returns (bool) {
        require(sender != address(0), "Transfer from zero address");
        require(recipient != address(0), "Transfer to zero address");
        require(amount > 0, "Transfer amount must be greater than zero");
        require(amount <= _balances[sender], "Insufficient balance");
        require(amount <= _allowances[sender][msg.sender], "Insufficient allowance");
        require(!isContract(sender), "Sender cannot be a contract");
        require(!isContract(recipient), "Recipient cannot be a contract");
        require(amount <= maxTxAmount, "Transfer amount exceeds the maxTxAmount");
        require(totalSupply.add(amount) <= maxSupply, "Total supply exceeds maximum supply");

        uint256 taxAmount = amount.mul(2).div(100);

        _transferInternal(sender, address(this), amount.sub(taxAmount));

        _transferInternal(sender, _owner, taxAmount);

        _transferInternal(address(this), recipient, amount.sub(taxAmount));

        _approve(sender, msg.sender, _allowances[sender][msg.sender].sub(amount));

        bytes32 auditHash = keccak256(abi.encodePacked("transfer", sender, recipient, amount, block.timestamp));
        _auditTrail[auditHash] = true;
        emit AuditTrail(auditHash);

        return true;
    }

     function getLastDepositTimestamp(address account) external view returns (uint256) {
        return _lastDepositTime[account];
    }

    function getRemainingTimeToWithdraw() external pure returns (uint256) {
        return 0; // There's no lockup period, so always return 0 for remaining time
    }

    function increaseAllowance(address spender, uint256 addedValue) external nonReentrant returns (bool) {
        require(spender != address(0), "Increase allowance to zero address");
        _allowances[msg.sender][spender] = _allowances[msg.sender][spender].add(addedValue);
        emit Approval(msg.sender, spender, _allowances[msg.sender][spender]);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) external nonReentrant returns (bool) {
        require(spender != address(0), "Decrease allowance to zero address");
        uint256 oldAllowance = _allowances[msg.sender][spender];
        if (subtractedValue >= oldAllowance) {
            _allowances[msg.sender][spender] = 0;
        } else {
            _allowances[msg.sender][spender] = oldAllowance.sub(subtractedValue);
        }
        emit Approval(msg.sender, spender, _allowances[msg.sender][spender]);
        return true;
    }

    function setMaxTxAmount(uint256 amount) external onlyOwner {
        require(amount > 0, "Amount must be greater than zero");
        require(amount <= maxSupply, "MaxTxAmount exceeds max supply");
        maxTxAmount = amount;
    }

    function renounceOwnership() external onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Transfer to zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }

    function emergencyWithdraw() external onlyOwner {
        _transferInternal(address(this), msg.sender, _balances[address(this)]);

        bytes32 auditHash = keccak256(abi.encodePacked("emergencyWithdraw", msg.sender, _balances[address(this)], block.timestamp));
        _auditTrail[auditHash] = true;
        emit AuditTrail(auditHash);
    }

    function isExcludedFromReward(address account) external pure returns (bool) {
        return account == address(0);
    }

    function isExcludedFromFee(address account) external pure returns (bool) {
        return account == address(0);
    }

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);
}
