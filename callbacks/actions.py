import binaryninja
import binaryninjaui

from binaryninja import PluginCommand, PluginCommandType

from typing import Union, Optional, overload

from ..core import const


class Action:
    full_name: str = None
    description: str = None
    desired_hotkey: str = None
    logger: binaryninja.Logger = None

    def __init__(self):
        self.logger = binaryninja.log.Logger(
            0, f"{const.plugin_name}.{self.short_name}"
        )

    @property
    def short_name(self):
        """
        Mostly for logging purposes.
        """
        return self.__class__.__name__

    def register(self):
        raise NotImplementedError

    def unregister(self):
        raise NotImplementedError


class PyToolsPluginCommand(Action):
    type_to_handler = {
        PluginCommandType.DefaultPluginCommand: PluginCommand.register,
        PluginCommandType.AddressPluginCommand: PluginCommand.register_for_address,
        PluginCommandType.RangePluginCommand: PluginCommand.register_for_range,
        PluginCommandType.FunctionPluginCommand: PluginCommand.register_for_function,
        PluginCommandType.LowLevelILFunctionPluginCommand: PluginCommand.register_for_low_level_il_function,
        PluginCommandType.LowLevelILInstructionPluginCommand: PluginCommand.register_for_low_level_il_instruction,
        PluginCommandType.MediumLevelILFunctionPluginCommand: PluginCommand.register_for_medium_level_il_function,
        PluginCommandType.MediumLevelILInstructionPluginCommand: PluginCommand.register_for_medium_level_il_instruction,
        PluginCommandType.HighLevelILFunctionPluginCommand: PluginCommand.register_for_high_level_il_function,
        PluginCommandType.HighLevelILInstructionPluginCommand: PluginCommand.register_for_high_level_il_instruction,
        PluginCommandType.ProjectPluginCommand: PluginCommand.register_for_project,
    }
    type: PluginCommandType = None

    def __init__(self):
        super().__init__()

        assert (
            self.full_name and self.description
        ), "Fullname and description must be filled"
        assert self.type is not None, "plugin command type must be set"

    # fmt: off
    @overload # register
    def activate(self, bv: binaryninja.BinaryView): raise NotImplementedError
    @overload # register_for_address
    def activate(self, bv: binaryninja.BinaryView, address: int): raise NotImplementedError
    @overload # register_for_function
    def activate(self, bv: binaryninja.BinaryView, function: binaryninja.Function): raise NotImplementedError
    @overload # register_for_high_level_il_function
    def activate(self, bv: binaryninja.BinaryView, function: binaryninja.HighLevelILFunction): raise NotImplementedError
    @overload # register_for_high_level_il_instruction
    def activate(self, bv: binaryninja.BinaryView, function: binaryninja.HighLevelILInstruction): raise NotImplementedError
    @overload # register_for_medium_level_il_function
    def activate(self, bv: binaryninja.BinaryView, function: binaryninja.MediumLevelILFunction): raise NotImplementedError
    @overload # register_for_medium_level_il_instruction
    def activate(self, bv: binaryninja.BinaryView, function: binaryninja.MediumLevelILInstruction): raise NotImplementedError
    @overload # register_for_low_level_il_function
    def activate(self, bv: binaryninja.BinaryView, function: binaryninja.LowLevelILFunction): raise NotImplementedError
    @overload # register_for_low_level_il_instruction
    def activate(self, bv: binaryninja.BinaryView, function: binaryninja.LowLevelILInstruction): raise NotImplementedError
    @overload # register_for_range
    def activate(self, bv: binaryninja.BinaryView, begin: int, end: int): raise NotImplementedError
    # fmt: on

    # fmt: off
    @overload # register
    def is_valid(self, bv: binaryninja.BinaryView) -> bool: raise NotImplementedError
    @overload # register_for_address
    def is_valid(self, bv: binaryninja.BinaryView, address: int) -> bool: raise NotImplementedError
    @overload # register_for_range
    def is_valid(self, bv: binaryninja.BinaryView, begin: int, end: int) -> bool: raise NotImplementedError
    @overload # register_for_function
    def is_valid(self, bv: binaryninja.BinaryView, function: binaryninja.Function) -> bool: raise NotImplementedError
    @overload # register_for_low_level_il_function
    def is_valid(self, bv: binaryninja.BinaryView, function: binaryninja.LowLevelILFunction) -> bool: raise NotImplementedError
    @overload # register_for_low_level_il_instruction
    def is_valid(self, bv: binaryninja.BinaryView, function: binaryninja.LowLevelILInstruction) -> bool: raise NotImplementedError
    @overload # register_for_medium_level_il_function
    def is_valid(self, bv: binaryninja.BinaryView, function: binaryninja.MediumLevelILFunction) -> bool: raise NotImplementedError
    @overload # register_for_medium_level_il_instruction
    def is_valid(self, bv: binaryninja.BinaryView, function: binaryninja.MediumLevelILInstruction) -> bool: raise NotImplementedError
    @overload # register_for_high_level_il_function
    def is_valid(self, bv: binaryninja.BinaryView, function: binaryninja.HighLevelILFunction) -> bool: raise NotImplementedError
    @overload # register_for_high_level_il_instruction
    def is_valid(self, bv: binaryninja.BinaryView, function: binaryninja.HighLevelILInstruction) -> bool: raise NotImplementedError
    # fmt: on

    def register(self):
        register = self.type_to_handler[self.type]
        register(
            f"{const.plugin_name}\\{self.full_name}",
            self.description,
            self.activate,
            self.is_valid,
        )


class PyToolsUIAction(Action):
    def __init__(self):
        super().__init__()
        assert (
            self.full_name and self.description
        ), "Fullname and description must be filled"

    # fmt: off
    @overload
    def activate(self): raise NotImplementedError
    @overload
    def activate(self, context: binaryninjaui.UIActionContext): raise NotImplementedError
    # fmt: on

    # fmt: off
    @overload
    def is_valid(self) -> bool: return True
    @overload
    def is_valid(self, context: binaryninjaui.UIActionContext) -> bool: return True
    # fmt: on

    def register(self):
        binaryninjaui.UIAction.registerAction(
            f"{const.plugin_name}\\{self.full_name}", self.desired_hotkey
        )
        binaryninjaui.UIActionHandler.globalActions().bindAction(
            f"{const.plugin_name}\\{self.full_name}",
            binaryninjaui.UIAction(self.activate, self.is_valid),
        )


class ActionManager:
    def __init__(self):
        self.__actions: list[Action] = list()

        self.logger: binaryninja.Logger = binaryninja.log.Logger(
            0, f"{const.plugin_name}.{self.__class__.__name__}"
        )

    def register(self, action: Action):
        self.logger.log_info("Registering %s action" % (action.short_name))

        if not action.full_name or not action.description:
            self.logger.log_error(
                "Full name and description must be filled for action to be registered, missing for %s"
                % (action.short_name)
            )
            return

        if isinstance(action, PyToolsPluginCommand) and action.desired_hotkey:
            self.logger.log_warn(
                f"Desired hotkey ({action.desired_hotkey}) for {action.short_name} is set, "
                "but setting default hotkey currently unavailable for PluginCommands, ignored"
            )

        self.__actions.append(action)
        action.register()

    def finalize(self):
        for action in self.__actions:
            action.unregister()


bn_action_manager = ActionManager()
