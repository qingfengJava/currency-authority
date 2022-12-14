package com.qingfeng.currency.authority.controller.auth;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.qingfeng.currency.authority.biz.service.auth.RoleAuthorityService;
import com.qingfeng.currency.authority.biz.service.auth.RoleOrgService;
import com.qingfeng.currency.authority.biz.service.auth.RoleService;
import com.qingfeng.currency.authority.biz.service.auth.UserRoleService;
import com.qingfeng.currency.authority.dto.auth.RoleAuthoritySaveDTO;
import com.qingfeng.currency.authority.dto.auth.RolePageDTO;
import com.qingfeng.currency.authority.dto.auth.RoleQueryDTO;
import com.qingfeng.currency.authority.dto.auth.RoleSaveDTO;
import com.qingfeng.currency.authority.dto.auth.RoleUpdateDTO;
import com.qingfeng.currency.authority.dto.auth.UserRoleSaveDTO;
import com.qingfeng.currency.authority.entity.auth.Role;
import com.qingfeng.currency.authority.entity.auth.RoleAuthority;
import com.qingfeng.currency.authority.entity.auth.UserRole;
import com.qingfeng.currency.authority.enumeration.auth.AuthorizeType;
import com.qingfeng.currency.base.BaseController;
import com.qingfeng.currency.base.R;
import com.qingfeng.currency.base.entity.SuperEntity;
import com.qingfeng.currency.database.mybatis.conditions.Wraps;
import com.qingfeng.currency.database.mybatis.conditions.query.LbqWrapper;
import com.qingfeng.currency.dozer.DozerUtils;
import com.qingfeng.currency.log.annotation.SysLog;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

/**
 * ???????????????
 * ??????
 *
 * @author ?????????Java
 * @version 1.0.0
 * @date 2022/9/18
 */
@Slf4j
@Validated
@RestController
@RequestMapping("/role")
@Api(value = "Role", tags = "??????")
public class RoleController extends BaseController {

    @Autowired
    private RoleService roleService;
    @Autowired
    private RoleAuthorityService roleAuthorityService;
    @Autowired
    private RoleOrgService roleOrgService;
    @Autowired
    private UserRoleService userRoleService;
    @Autowired
    private DozerUtils dozer;

    @ApiOperation(value = "??????????????????", notes = "??????????????????")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "current", value = "?????????", dataType = "long", paramType = "query", defaultValue = "1"),
            @ApiImplicitParam(name = "size", value = "??????????????????", dataType = "long", paramType = "query", defaultValue = "10"),
    })
    @GetMapping("/page")
    @SysLog("??????????????????")
    public R<IPage<Role>> page(RolePageDTO param) {
        IPage<Role> page = getPage();
        Role role = dozer.map(param, Role.class);
        // ???????????????null???????????????
        LbqWrapper<Role> query = Wraps.lbQ(role)
                .geHeader(Role::getCreateTime, param.getStartCreateTime())
                .leFooter(Role::getCreateTime, param.getEndCreateTime())
                .orderByDesc(Role::getId);
        roleService.page(page, query);
        return success(page);
    }

    @ApiOperation(value = "????????????", notes = "????????????")
    @GetMapping("/{id}")
    @SysLog("????????????")
    public R<RoleQueryDTO> get(@PathVariable Long id) {
        Role role = roleService.getById(id);

        RoleQueryDTO roleQueryDTO = dozer.map(role, RoleQueryDTO.class);
        List<Long> orgList = roleOrgService.listOrgByRoleId(role.getId());
        roleQueryDTO.setOrgList(orgList);

        return success(roleQueryDTO);
    }

    @ApiOperation(value = "??????????????????", notes = "??????????????????")
    @GetMapping("/check/{code}")
    @SysLog("????????????")
    public R<Boolean> check(@PathVariable String code) {
        return success(roleService.check(code));
    }

    @ApiOperation(value = "????????????", notes = "??????????????????????????????")
    @PostMapping
    @SysLog("????????????")
    public R<RoleSaveDTO> save(@RequestBody @Validated RoleSaveDTO data) {
        roleService.saveRole(data, getUserId());
        return success(data);
    }

    @ApiOperation(value = "????????????", notes = "??????????????????????????????")
    @PutMapping
    @SysLog("????????????")
    public R<RoleUpdateDTO> update(@RequestBody @Validated(SuperEntity.Update.class) RoleUpdateDTO data) {
        roleService.updateRole(data, getUserId());
        return success(data);
    }

    @ApiOperation(value = "????????????", notes = "??????id??????????????????")
    @DeleteMapping
    @SysLog("????????????")
    public R<Boolean> delete(@RequestParam("ids[]") List<Long> ids) {
        roleService.removeById(ids);
        return success(true);
    }

    @ApiOperation(value = "?????????????????????", notes = "?????????????????????")
    @PostMapping("/user")
    @SysLog("?????????????????????")
    public R<Boolean> saveUserRole(@RequestBody UserRoleSaveDTO userRole) {
        return success(roleAuthorityService.saveUserRole(userRole));
    }

    @ApiOperation(value = "?????????????????????", notes = "?????????????????????")
    @GetMapping("/user/{roleId}")
    @SysLog("?????????????????????")
    public R<List<Long>> findUserIdByRoleId(@PathVariable Long roleId) {
        List<UserRole> list = userRoleService.list(Wraps.<UserRole>lbQ().eq(UserRole::getRoleId, roleId));
        return success(list.stream().mapToLong(UserRole::getUserId).boxed().collect(Collectors.toList()));
    }

    @ApiOperation(value = "???????????????????????????id??????", notes = "???????????????????????????id??????")
    @GetMapping("/authority/{roleId}")
    @SysLog("???????????????????????????")
    public R<RoleAuthoritySaveDTO> findAuthorityIdByRoleId(@PathVariable Long roleId) {
        List<RoleAuthority> list = roleAuthorityService.list(Wraps.<RoleAuthority>lbQ().eq(RoleAuthority::getRoleId, roleId));
        List<Long> menuIdList = list.stream().filter(item -> AuthorizeType.MENU.eq(item.getAuthorityType())).mapToLong(RoleAuthority::getAuthorityId).boxed().collect(Collectors.toList());
        List<Long> resourceIdList = list.stream().filter(item -> AuthorizeType.RESOURCE.eq(item.getAuthorityType())).mapToLong(RoleAuthority::getAuthorityId).boxed().collect(Collectors.toList());
        RoleAuthoritySaveDTO roleAuthority = RoleAuthoritySaveDTO.builder()
                .menuIdList(menuIdList).resourceIdList(resourceIdList)
                .build();
        return success(roleAuthority);
    }

    @ApiOperation(value = "?????????????????????", notes = "?????????????????????")
    @PostMapping("/authority")
    @SysLog("?????????????????????")
    public R<Boolean> saveRoleAuthority(@RequestBody RoleAuthoritySaveDTO roleAuthoritySaveDTO) {
        return success(roleAuthorityService.saveRoleAuthority(roleAuthoritySaveDTO));
    }

    @ApiOperation(value = "??????????????????????????????ID", notes = "??????????????????????????????ID")
    @GetMapping("/codes")
    @SysLog("??????????????????????????????ID")
    public R<List<Long>> findUserIdByCode(@RequestParam(value = "codes") String[] codes) {
        return success(roleService.findUserIdByCode(codes));
    }
}