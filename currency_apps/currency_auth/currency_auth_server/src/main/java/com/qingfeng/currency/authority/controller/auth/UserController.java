package com.qingfeng.currency.authority.controller.auth;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.qingfeng.currency.authority.biz.service.auth.RoleService;
import com.qingfeng.currency.authority.biz.service.auth.UserService;
import com.qingfeng.currency.authority.biz.service.core.OrgService;
import com.qingfeng.currency.authority.biz.service.core.StationService;
import com.qingfeng.currency.authority.dto.auth.UserPageDTO;
import com.qingfeng.currency.authority.dto.auth.UserRoleDTO;
import com.qingfeng.currency.authority.dto.auth.UserSaveDTO;
import com.qingfeng.currency.authority.dto.auth.UserUpdateAvatarDTO;
import com.qingfeng.currency.authority.dto.auth.UserUpdateDTO;
import com.qingfeng.currency.authority.dto.auth.UserUpdatePasswordDTO;
import com.qingfeng.currency.authority.entity.auth.Role;
import com.qingfeng.currency.authority.entity.auth.User;
import com.qingfeng.currency.authority.entity.core.Org;
import com.qingfeng.currency.base.BaseController;
import com.qingfeng.currency.base.R;
import com.qingfeng.currency.base.entity.SuperEntity;
import com.qingfeng.currency.database.mybatis.conditions.Wraps;
import com.qingfeng.currency.database.mybatis.conditions.query.LbqWrapper;
import com.qingfeng.currency.dozer.DozerUtils;
import com.qingfeng.currency.log.annotation.SysLog;
import com.qingfeng.currency.user.feign.UserQuery;
import com.qingfeng.currency.user.model.SysOrg;
import com.qingfeng.currency.user.model.SysRole;
import com.qingfeng.currency.user.model.SysStation;
import com.qingfeng.currency.user.model.SysUser;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
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

import java.util.Arrays;
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
@RequestMapping("/user")
@Api(value = "User", tags = "??????")
public class UserController extends BaseController {

    @Autowired
    private UserService userService;
    @Autowired
    private OrgService orgService;
    @Autowired
    private RoleService roleService;
    @Autowired
    private StationService stationService;
    @Autowired
    private DozerUtils dozer;

    @ApiOperation(value = "??????????????????", notes = "??????????????????")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "current", value = "??????", dataType = "long", paramType = "query", defaultValue = "1"),
            @ApiImplicitParam(name = "size", value = "????????????", dataType = "long", paramType = "query", defaultValue = "10"),
    })
    @GetMapping("/page")
    @SysLog("??????????????????")
    public R<IPage<User>> page(UserPageDTO userPage) {
        IPage<User> page = getPage();

        User user = dozer.map2(userPage, User.class);
        if (userPage.getOrgId() != null && userPage.getOrgId() >= 0) {
            user.setOrgId(null);
        }
        LbqWrapper<User> wrapper = Wraps.lbQ(user);
        if (userPage.getOrgId() != null && userPage.getOrgId() >= 0) {
            List<Org> children = orgService.findChildren(Arrays.asList(userPage.getOrgId()));
            wrapper.in(User::getOrgId, children.stream().mapToLong(Org::getId).boxed().collect(Collectors.toList()));
        }
        wrapper.geHeader(User::getCreateTime, userPage.getStartCreateTime())
                .leFooter(User::getCreateTime, userPage.getEndCreateTime())
                .like(User::getName, userPage.getName())
                .like(User::getAccount, userPage.getAccount())
                .like(User::getEmail, userPage.getEmail())
                .like(User::getMobile, userPage.getMobile())
                .eq(User::getSex, userPage.getSex())
                .eq(User::getStatus, userPage.getStatus())
                .orderByDesc(User::getId);
//        userService.page(page, wrapper);

        userService.findPage(page, wrapper);
        return success(page);
    }

    @ApiOperation(value = "????????????", notes = "????????????")
    @GetMapping("/{id}")
    @SysLog("????????????")
    public R<User> get(@PathVariable Long id) {
        return success(userService.getById(id));
    }

    @ApiOperation(value = "??????????????????", notes = "??????????????????")
    @GetMapping("/find")
    @SysLog("??????????????????")
    public R<List<Long>> findAllUserId() {
        return success(userService.list().stream().mapToLong(User::getId).boxed().collect(Collectors.toList()));
    }

    @ApiOperation(value = "????????????", notes = "??????????????????????????????")
    @PostMapping
    @SysLog("????????????")
    public R<User> save(@RequestBody @Validated UserSaveDTO data) {
        User user = dozer.map(data, User.class);
        userService.saveUser(user);
        return success(user);
    }

    @ApiOperation(value = "????????????", notes = "??????????????????????????????")
    @PutMapping
    @SysLog("????????????")
    public R<User> update(@RequestBody @Validated(SuperEntity.Update.class) UserUpdateDTO data) {
        User user = dozer.map(data, User.class);
        userService.updateUser(user);
        return success(user);
    }

    @ApiOperation(value = "????????????", notes = "????????????")
    @PutMapping("/avatar")
    @SysLog("????????????")
    public R<User> avatar(@RequestBody @Validated(SuperEntity.Update.class) UserUpdateAvatarDTO data) {
        User user = dozer.map(data, User.class);
        userService.updateUser(user);
        return success(user);
    }

    @ApiOperation(value = "????????????", notes = "????????????")
    @PutMapping("/password")
    @SysLog("????????????")
    public R<Boolean> updatePassword(@RequestBody UserUpdatePasswordDTO data) {
        return success(userService.updatePassword(data));
    }

    @ApiOperation(value = "????????????", notes = "????????????")
    @GetMapping("/reset")
    @SysLog("????????????")
    public R<Boolean> resetTx(@RequestParam("ids[]") List<Long> ids) {
        userService.reset(ids);
        return success();
    }

    @ApiOperation(value = "????????????", notes = "??????id??????????????????")
    @DeleteMapping
    @SysLog("????????????")
    public R<Boolean> delete(@RequestParam("ids[]") List<Long> ids) {
        userService.remove(ids);
        return success(true);
    }

    @ApiOperation(value = "??????????????????", notes = "??????????????????")
    @PostMapping(value = "/anno/id/{id}")
    public R<SysUser> getById(@PathVariable Long id, @RequestBody UserQuery query) {
        User user = userService.getById(id);
        if (user == null) {
            return success(null);
        }
        SysUser sysUser = dozer.map(user, SysUser.class);

        if (query.getFull() || query.getOrg()) {
            sysUser.setOrg(dozer.map(orgService.getById(user.getOrgId()), SysOrg.class));
        }
        if (query.getFull() || query.getStation()) {
            sysUser.setStation(dozer.map(stationService.getById(user.getStationId()), SysStation.class));
        }

        if (query.getFull() || query.getRoles()) {
            List<Role> list = roleService.findRoleByUserId(id);
            sysUser.setRoles(dozer.mapList(list, SysRole.class));
        }

        return success(sysUser);
    }

    @ApiOperation(value = "??????????????????????????????", notes = "??????????????????????????????")
    @GetMapping(value = "/role/{roleId}")
    public R<UserRoleDTO> findUserByRoleId(@ApiParam(value = "??????Id", required = true) @PathVariable("roleId") Long roleId,
                                           @ApiParam(value = "??????account?????????name", required = true) @RequestParam(value = "keyword", required = false) String keyword) {
        List<User> list = userService.findUserByRoleId(roleId, keyword);
        List<Long> idList = list.stream().mapToLong(User::getId).boxed().collect(Collectors.toList());
        return success(UserRoleDTO.builder().idList(idList).userList(list).build());
    }
}