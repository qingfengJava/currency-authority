package com.qingfeng.currency.authority.controller.auth;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.qingfeng.currency.auth.server.utils.JwtTokenServerUtils;
import com.qingfeng.currency.auth.utils.JwtUserInfo;
import com.qingfeng.currency.authority.biz.service.auth.MenuService;
import com.qingfeng.currency.authority.dto.auth.MenuSaveDTO;
import com.qingfeng.currency.authority.dto.auth.MenuTreeDTO;
import com.qingfeng.currency.authority.dto.auth.MenuUpdateDTO;
import com.qingfeng.currency.authority.dto.auth.RouterMeta;
import com.qingfeng.currency.authority.dto.auth.VueRouter;
import com.qingfeng.currency.authority.entity.auth.Menu;
import com.qingfeng.currency.base.BaseController;
import com.qingfeng.currency.base.R;
import com.qingfeng.currency.base.entity.SuperEntity;
import com.qingfeng.currency.database.mybatis.conditions.Wraps;
import com.qingfeng.currency.database.mybatis.conditions.query.LbqWrapper;
import com.qingfeng.currency.dozer.DozerUtils;
import com.qingfeng.currency.log.annotation.SysLog;
import com.qingfeng.currency.utils.TreeUtil;
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

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

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
@RequestMapping("/menu")
@Api(value = "Menu", tags = "??????")
public class MenuController extends BaseController {

    @Autowired
    private MenuService menuService;
    @Autowired
    private DozerUtils dozer;

    @ApiOperation(value = "??????????????????", notes = "??????????????????")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "current", value = "?????????", dataType = "long", paramType = "query", defaultValue = "1"),
            @ApiImplicitParam(name = "size", value = "??????????????????", dataType = "long", paramType = "query", defaultValue = "10"),
    })
    @GetMapping("/page")
    @SysLog("??????????????????")
    public R<IPage<Menu>> page(Menu data) {
        IPage<Menu> page = getPage();
        // ???????????????null???????????????
        LbqWrapper<Menu> query = Wraps.lbQ(data).orderByDesc(Menu::getUpdateTime);
        menuService.page(page, query);
        return success(page);
    }

    @ApiOperation(value = "????????????", notes = "????????????")
    @GetMapping("/{id}")
    @SysLog("????????????")
    public R<Menu> get(@PathVariable Long id) {
        return success(menuService.getById(id));
    }

    @ApiOperation(value = "????????????", notes = "??????????????????????????????")
    @PostMapping
    @SysLog("????????????")
    public R<Menu> save(@RequestBody @Validated MenuSaveDTO data) {
        Menu menu = dozer.map(data, Menu.class);
        menuService.save(menu);
        return success(menu);
    }

    @ApiOperation(value = "????????????", notes = "??????????????????????????????")
    @PutMapping
    @SysLog("????????????")
    public R<Menu> update(@RequestBody @Validated(SuperEntity.Update.class) MenuUpdateDTO data) {
        Menu menu = dozer.map(data, Menu.class);
        menuService.updateById(menu);
        return success(menu);
    }

    @ApiOperation(value = "????????????", notes = "??????id??????????????????")
    @DeleteMapping
    @SysLog("????????????")
    public R<Boolean> delete(@RequestParam("ids[]") List<Long> ids) {
        menuService.removeByIds(ids);
        return success(true);
    }

    @ApiOperation(value = "?????????????????????????????????", notes = "?????????????????????????????????")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "group", value = "?????????", dataType = "string", paramType = "query"),
            @ApiImplicitParam(name = "userId", value = "??????id", dataType = "long", paramType = "query"),
    })
    @GetMapping
    @Deprecated
    public R<List<MenuTreeDTO>> myMenus(@RequestParam(value = "group", required = false) String group,
                                        @RequestParam(value = "userId", required = false) Long userId) {
        if (userId == null || userId <= 0) {
            userId = getUserId();
        }
        List<Menu> list = menuService.findVisibleMenu(group, userId);
        List<MenuTreeDTO> treeList = dozer.mapList(list, MenuTreeDTO.class);

        List<MenuTreeDTO> tree = TreeUtil.build(treeList);
        return success(tree);
    }

    private List<VueRouter> buildSuperAdminRouter() {
        List<VueRouter> tree = new ArrayList<>();
        List<VueRouter> children = new ArrayList<>();

        VueRouter defaults = new VueRouter();
        defaults.setPath("/defaults");
        defaults.setComponent("Layout");
        defaults.setHidden(false);
        defaults.setAlwaysShow(true);
        defaults.setMeta(RouterMeta.builder()
                .title("????????????").icon("el-icon-coin").breadcrumb(true)
                .build());
        defaults.setId(-1L);
        defaults.setChildren(children);

        tree.add(defaults);
        return tree;
    }

    @Autowired
    private JwtTokenServerUtils jwtTokenServerUtils;

    @ApiImplicitParams({
            @ApiImplicitParam(name = "group", value = "?????????", dataType = "string", paramType = "query"),
            @ApiImplicitParam(name = "userId", value = "??????id", dataType = "long", paramType = "query"),
    })
    @ApiOperation(value = "??????????????????????????????????????????", notes = "??????????????????????????????????????????")
    @GetMapping("/router")
    public R<List<VueRouter>> myRouter(@RequestParam(value = "group", required = false) String group,
                                       @RequestParam(value = "userId", required = false) Long userId, HttpServletRequest request) {
        if (userId == null || userId <= 0) {
            userId = getUserId();
        }
        if(userId == 0){
            String userToken = request.getHeader("token");
            JwtUserInfo userInfo = jwtTokenServerUtils.getUserInfo(userToken);
            userId = userInfo.getUserId();
        }
        List<Menu> list = menuService.findVisibleMenu(group, userId);
        List<VueRouter> treeList = dozer.mapList(list, VueRouter.class);
        return success(TreeUtil.build(treeList));
    }

    @ApiOperation(value = "???????????????????????????", notes = "???????????????????????????")
    @GetMapping("/admin/router")
    public R<List<VueRouter>> adminRouter() {
        return success(buildSuperAdminRouter());
    }

    @ApiOperation(value = "???????????????????????????",
            notes = "????????????????????????????????????????????? ???????????????????????????????????????????????????????????????????????????????????????????????????")
    @GetMapping("/tree")
    @SysLog("???????????????????????????")
    public R<List<MenuTreeDTO>> allTree() {
        List<Menu> list = menuService.list(Wraps.<Menu>lbQ().orderByAsc(Menu::getSortValue));
        List<MenuTreeDTO> treeList = dozer.mapList(list, MenuTreeDTO.class);
        return success(TreeUtil.build(treeList));
    }
}